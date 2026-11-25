package node

import (
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"certrot/certs"
	"certrot/model"
	"certrot/store"
)

func setupNode(t *testing.T) (*Node, *store.Store, *store.Material, *store.Material) {
	t.Helper()
	ca, err := certs.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New()
	leaf1, err := ca.NewLeaf("t", big.NewInt(1), time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := ca.NewLeaf("t2", big.NewInt(2), time.Now().Add(-time.Minute), time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	v1 := &store.Material{Version: "v1", RV: 1, CertPEM: leaf1.CertPEM, KeyPEM: leaf1.KeyPEM,
		EnvB64: leaf1.EnvB64, Serial: leaf1.Cert.SerialNumber.String(), NotAfter: leaf1.Cert.NotAfter}
	v2 := &store.Material{Version: "v2", RV: 2, CertPEM: leaf2.CertPEM, KeyPEM: leaf2.KeyPEM,
		EnvB64: leaf2.EnvB64, Serial: leaf2.Cert.SerialNumber.String(), NotAfter: leaf2.Cert.NotAfter}
	key := store.ObjectKey{Name: "sec", Key: "tls.crt"}
	st.Put(key, v1)

	nd, err := New("n1", filepath.Join(t.TempDir(), "node"), st, 100*time.Millisecond,
		rand.New(rand.NewSource(1)))
	if err != nil {
		t.Fatal(err)
	}
	return nd, st, v1, v2
}

func newContainer(id string, mount model.MountMode) *model.Container {
	return &model.Container{
		ID: id, PodID: "p", Workload: "wl", Namespace: "ns", Kind: "Deployment",
		Tier: 2, Node: "n1", Mount: mount, Read: model.ReadOnce,
		SecretName: "sec", CertKey: "tls.crt",
	}
}

func TestVolumeAtomicSwap(t *testing.T) {
	nd, st, v1, v2 := setupNode(t)
	c := newContainer("c1", model.MountVolume)
	if err := nd.PreparePaths(c); err != nil {
		t.Fatal(err)
	}
	nd.Sync([]*model.Container{c})

	got, err := os.ReadFile(c.CertPath)
	if err != nil || string(got) != string(v1.CertPEM) {
		t.Fatalf("initial volume render mismatch: %v", err)
	}
	// Real kubelet layout: leaf symlink through ..data.
	link, err := os.Readlink(c.CertPath)
	if err != nil || link != filepath.Join("..data", "tls.crt") {
		t.Fatalf("leaf entry should be symlink ..data/tls.crt, got %q err=%v", link, err)
	}

	st.Put(store.ObjectKey{Name: "sec", Key: "tls.crt"}, v2)
	nd.Sync([]*model.Container{c})

	got, err = os.ReadFile(c.CertPath)
	if err != nil || string(got) != string(v2.CertPEM) {
		t.Fatalf("volume did not switch to v2 after sync")
	}
	// Old timestamped dir must have been garbage collected.
	entries, _ := os.ReadDir(c.VolumeDir)
	tsDirs := 0
	for _, e := range entries {
		if len(e.Name()) > 2 && e.Name()[:2] == ".." && e.Name() != "..data" && e.Name() != "..data_tmp" {
			tsDirs++
		}
	}
	if tsDirs != 1 {
		t.Fatalf("expected exactly 1 timestamped dir after GC, got %d", tsDirs)
	}
	// Stable leaf entry itself must be untouched.
	link2, _ := os.Readlink(c.CertPath)
	if link2 != link {
		t.Fatalf("leaf symlink changed during swap: %q -> %q", link, link2)
	}
	_ = v1
}

func TestSubPathFrozenUntilRestart(t *testing.T) {
	nd, st, _, v2 := setupNode(t)
	c := newContainer("c2", model.MountSubPath)
	if err := nd.PreparePaths(c); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(c.CertPath)

	st.Put(store.ObjectKey{Name: "sec", Key: "tls.crt"}, v2)
	nd.Sync([]*model.Container{c})
	after, _ := os.ReadFile(c.CertPath)
	if string(before) != string(after) {
		t.Fatal("subPath file changed despite no propagation (should stay v1)")
	}

	if err := nd.PrepareRestart(c); err != nil {
		t.Fatal(err)
	}
	afterRestart, _ := os.ReadFile(c.CertPath)
	if string(afterRestart) != string(v2.CertPEM) {
		t.Fatal("subPath did not pick up v2 after restart re-render")
	}
}

func TestEnvFrozenUntilRestart(t *testing.T) {
	nd, st, v1, v2 := setupNode(t)
	c := newContainer("c3", model.MountEnv)
	if err := nd.PreparePaths(c); err != nil {
		t.Fatal(err)
	}
	env1, _ := os.ReadFile(c.EnvPath)
	if !containsBytes(env1, []byte(v1.EnvB64)) {
		t.Fatal("env render missing v1 material")
	}

	st.Put(store.ObjectKey{Name: "sec", Key: "tls.crt"}, v2)
	nd.Sync([]*model.Container{c})
	env2, _ := os.ReadFile(c.EnvPath)
	if !containsBytes(env2, []byte(v1.EnvB64)) || containsBytes(env2, []byte(v2.EnvB64)) {
		t.Fatal("env file changed despite being start-time rendered")
	}

	if err := nd.PrepareRestart(c); err != nil {
		t.Fatal(err)
	}
	env3, _ := os.ReadFile(c.EnvPath)
	if !containsBytes(env3, []byte(v2.EnvB64)) {
		t.Fatal("env did not pick up v2 after restart re-render")
	}
}

func containsBytes(haystack, needle []byte) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
