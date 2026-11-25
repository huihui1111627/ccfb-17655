package sim

import (
	"context"
	"math/big"
	"math/rand"
	"sync"
	"testing"
	"time"

	"certrot/app"
	"certrot/certs"
	"certrot/model"
	"certrot/node"
	"certrot/store"
)

func bigSerial(n int64) *big.Int { return big.NewInt(n) }
func newTestRand() *rand.Rand    { return rand.New(rand.NewSource(1)) }
func newRWMu() *sync.RWMutex     { return &sync.RWMutex{} }

// TestMountReadMatrix verifies the central claim of the simulator against
// real filesystem operations and a real fsnotify backend: every legal
// mount×read combination behaves exactly as the static scanner predicts,
// and restarting the "never" containers heals all of them.
func TestMountReadMatrix(t *testing.T) {
	dir := t.TempDir()
	ca, err := certs.NewCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New()

	// v1 material.
	v1Leaf, err := ca.NewLeaf("matrix-tls", bigSerial(1), time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	v1 := &store.Material{
		Version: "v1", RV: 1, CertPEM: v1Leaf.CertPEM, KeyPEM: v1Leaf.KeyPEM,
		EnvB64: v1Leaf.EnvB64, Serial: v1Leaf.Cert.SerialNumber.String(),
		NotAfter: time.Now().Add(time.Hour),
	}
	key := store.ObjectKey{Name: "matrix-tls", Key: "tls.crt"}
	st.Put(key, v1)

	nd, err := node.New("node-test", dir+"/node", st, 200*time.Millisecond, newTestRand())
	if err != nil {
		t.Fatal(err)
	}

	type combo struct {
		mount model.MountMode
		read  model.ReadMode
		want  bool // expected auto-update without restart
	}
	combos := []combo{
		{model.MountVolume, model.ReadOnce, false},
		{model.MountVolume, model.ReadPoll, true},
		{model.MountVolume, model.ReadWatchFile, false},
		{model.MountVolume, model.ReadWatchDir, true},
		{model.MountVolume, model.ReadWatchDirFiltered, false},
		{model.MountVolume, model.ReadPollWatch, true},
		{model.MountSubPath, model.ReadOnce, false},
		{model.MountSubPath, model.ReadPoll, false},
		{model.MountSubPath, model.ReadWatchFile, false},
		{model.MountSubPath, model.ReadWatchDir, false},
		{model.MountSubPath, model.ReadWatchDirFiltered, false},
		{model.MountSubPath, model.ReadPollWatch, false},
		{model.MountEnv, model.ReadOnce, false},
		{model.MountEnv, model.ReadPoll, false},
	}

	runner := app.NewRunner(func(c *model.Container) error { return nd.PrepareRestart(c) })
	runner.RegisterMaterial(v1.Serial, "v1")

	var cs []*model.Container
	for _, cb := range combos {
		c := &model.Container{
			ID: string(cb.mount) + "-" + string(cb.read), PodID: "p",
			Workload:  "wl-" + string(cb.mount) + "-" + string(cb.read),
			Namespace: "test", Kind: "Deployment", Tier: 2, Node: "node-test",
			Mount: cb.mount, Read: cb.read, SecretName: "matrix-tls", CertKey: "tls.crt",
			PollInterval: 250 * time.Millisecond, Status: "pending", Mu: newRWMu(),
		}
		if err := nd.PreparePaths(c); err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	// Bootstrap whole-volume renders before any app starts (mirrors sim.Start).
	nd.Sync(cs)
	for _, c := range cs {
		runner.Start(c)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go nd.Run(ctx, cs)
	t.Cleanup(cancel)

	// Everyone must start on v1.
	time.Sleep(300 * time.Millisecond)
	for _, c := range cs {
		c.Mu.RLock()
		got := c.LoadedVersion
		c.Mu.RUnlock()
		if got != "v1" {
			t.Fatalf("%s/%s started on %q, want v1", c.Mount, c.Read, got)
		}
	}

	// Rotate: v2 with a fresh serial.
	v2Leaf, err := ca.NewLeaf("matrix-tls-v2", bigSerial(2), time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	v2 := &store.Material{
		Version: "v2", RV: 2, CertPEM: v2Leaf.CertPEM, KeyPEM: v2Leaf.KeyPEM,
		EnvB64: v2Leaf.EnvB64, Serial: v2Leaf.Cert.SerialNumber.String(),
		NotAfter: time.Now().Add(24 * time.Hour),
	}
	st.Put(key, v2)
	runner.RegisterMaterial(v2.Serial, "v2")

	// Worst-case bound here: node sync 200ms*1.2 + poll 250ms + slack.
	time.Sleep(3 * time.Second)

	var neverUpdated []*model.Container
	for i, cb := range combos {
		c := cs[i]
		c.Mu.RLock()
		got := c.LoadedVersion
		c.Mu.RUnlock()
		updated := got == "v2"
		if updated != cb.want {
			t.Errorf("%s/%s: auto-update=%v want %v (loaded=%s)", cb.mount, cb.read, updated, cb.want, got)
		}
		if !updated {
			neverUpdated = append(neverUpdated, c)
		}
	}

	// Restart every container that failed to self-heal; all must end on v2.
	for _, c := range neverUpdated {
		if err := runner.Restart(c); err != nil {
			t.Fatalf("restart %s: %v", c.ID, err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	for _, c := range cs {
		c.Mu.RLock()
		got := c.LoadedVersion
		c.Mu.RUnlock()
		if got != "v2" {
			t.Errorf("%s/%s still on %q after restart", c.Mount, c.Read, got)
		}
	}
}
