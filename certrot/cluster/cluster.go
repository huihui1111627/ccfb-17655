// Package cluster generates a realistic fleet: hundreds of workloads spread
// over nodes/namespaces, mixing every mount and read strategy, including
// multi-container pods that combine several strategies at once.
package cluster

import (
	"fmt"
	"math/big"
	"math/rand"
	"path/filepath"
	"sync"
	"time"

	"certrot/certs"
	"certrot/model"
	"certrot/node"
	"certrot/store"
)

// Config controls fleet generation.
type Config struct {
	WorkloadCount int
	NodeCount     int
	DataDir       string
	OldCertTTL    time.Duration // v1 cert validity from now (the "expires in 3 days" cert)
	Seed          int64
	// NodeSyncBase is node 1's kubelet sync period; node i gets
	// NodeSyncBase*(i+1)-ish spacing. Zero falls back to demo-scale defaults.
	NodeSyncBase time.Duration
}

// SecretSpec is one simulated secret object and every version it ever holds.
type SecretSpec struct {
	Name     string
	Tier     int
	NotAfter time.Time
	Versions map[string]*store.Material // version label -> material
}

// BuildResult is everything the rest of the simulation needs to start.
type BuildResult struct {
	Store      *store.Store
	Secrets    []*SecretSpec
	Workloads  []*model.Workload
	Containers []*model.Container
	Nodes      []*node.Node
	// SerialVersion maps cert serial -> v1/v2 for the app runner.
	SerialVersion map[string]string
}

var namespaces = []string{"payment", "order", "gateway", "platform", "observability"}
var kinds = []string{"Deployment", "StatefulSet", "DaemonSet", "CronJob"}
var workloadPrefixes = []string{"api", "worker", "scheduler", "ingress", "auth", "billing",
	"inventory", "notify", "report", "etl", "proxy", "cache", "search", "ledger", "webhook"}

// weighted choice helper.
func pick(rng *rand.Rand, weights []int, items []string) string {
	total := 0
	for _, w := range weights {
		total += w
	}
	r := rng.Intn(total)
	for i, w := range weights {
		if r < w {
			return items[i]
		}
		r -= w
	}
	return items[len(items)-1]
}

// Build generates the whole fleet and the v1 secrets it starts with.
func Build(cfg Config, ca *certs.CA, st *store.Store, rng *rand.Rand) (*BuildResult, error) {
	// ---- secrets -------------------------------------------------------
	secretDefs := []struct {
		name string
		tier int
	}{
		{"payment-tls", 0},
		{"gateway-tls", 0},
		{"service-mesh-tls", 1},
		{"internal-app-tls", 2},
	}
	notAfterV1 := time.Now().Add(cfg.OldCertTTL)
	secrets := make([]*SecretSpec, 0, len(secretDefs))
	serialCounter := int64(1000)
	for _, sd := range secretDefs {
		leaf, err := ca.NewLeaf(sd.name, big.NewInt(serialCounter), time.Now().Add(-time.Minute), notAfterV1)
		if err != nil {
			return nil, err
		}
		serialCounter++
		mat := &store.Material{
			Version: "v1", RV: 1, CertPEM: leaf.CertPEM, KeyPEM: leaf.KeyPEM,
			EnvB64: leaf.EnvB64, Serial: leaf.Cert.SerialNumber.String(), NotAfter: notAfterV1,
		}
		key := store.ObjectKey{Name: sd.name, Key: "tls.crt"}
		st.Put(key, mat)
		secrets = append(secrets, &SecretSpec{
			Name: sd.name, Tier: sd.tier, NotAfter: notAfterV1,
			Versions: map[string]*store.Material{"v1": mat},
		})
	}

	// ---- nodes ---------------------------------------------------------
	nodes := make([]*node.Node, cfg.NodeCount)
	for i := range nodes {
		name := fmt.Sprintf("node-%d", i+1)
		// kubelet sync period in the field is typically 20s–1min. Nodes in the
		// sim get per-node fixed periods spread across that range (+ runtime
		// jitter in node.Run), compressed for the demo via cfg scaling.
		base := time.Duration(6+i*2) * time.Second
		if cfg.NodeSyncBase > 0 {
			base = cfg.NodeSyncBase + time.Duration(i)*cfg.NodeSyncBase/3
		}
		n, err := node.New(name, filepath.Join(cfg.DataDir, "nodes", name), st, base, rng)
		if err != nil {
			return nil, err
		}
		nodes[i] = n
	}

	// ---- workloads -----------------------------------------------------
	// Weight distribution (percent) for mount and read modes is enforced via
	// weighted pickers below, including the combination cases.
	var workloads []*model.Workload
	var containers []*model.Container
	cid := 0
	for w := 0; w < cfg.WorkloadCount; w++ {
		ns := namespaces[rng.Intn(len(namespaces))]
		prefix := workloadPrefixes[rng.Intn(len(workloadPrefixes))]
		name := fmt.Sprintf("%s-%s-%d", prefix, ns[:2], w)
		kind := kinds[rng.Intn(len(kinds))]
		nd := nodes[rng.Intn(len(nodes))]

		// ~8% of workloads are multi-container pods combining strategies.
		containerN := 1
		if rng.Float64() < 0.08 {
			containerN = 2 + rng.Intn(2)
		}

		wl := &model.Workload{
			ID: fmt.Sprintf("wl-%d", w), Namespace: ns, Name: name, Kind: kind, Node: nd.Name,
		}
		secret := secrets[rng.Intn(len(secrets))]
		wl.Tier = secret.Tier

		for k := 0; k < containerN; k++ {
			cid++
			mount := model.MountMode(pick(rng,
				[]int{55, 30, 15},
				[]string{string(model.MountVolume), string(model.MountSubPath), string(model.MountEnv)}))
			read := model.ReadMode(pickRead(rng, mount))

			c := &model.Container{
				ID:           fmt.Sprintf("c-%04d", cid),
				PodID:        wl.ID,
				Workload:     name,
				Namespace:    ns,
				Kind:         kind,
				Tier:         secret.Tier,
				Node:         nd.Name,
				Mount:        mount,
				Read:         read,
				SecretName:   secret.Name,
				CertKey:      "tls.crt",
				PollInterval: time.Duration(6+rng.Intn(15)) * time.Second,
				Status:       "pending",
				Mu:           &sync.RWMutex{},
			}
			if containerN > 1 {
				c.Workload = name + "/" + fmt.Sprintf("sidecar-%d", k)
			}
			if err := nd.PreparePaths(c); err != nil {
				return nil, err
			}
			wl.Containers = append(wl.Containers, c)
			containers = append(containers, c)
		}
		workloads = append(workloads, wl)
	}

	serialVersion := map[string]string{}
	for _, s := range secrets {
		for v, m := range s.Versions {
			serialVersion[m.Serial] = v
		}
	}

	return &BuildResult{
		Store: st, Secrets: secrets, Workloads: workloads,
		Containers: containers, Nodes: nodes, SerialVersion: serialVersion,
	}, nil
}

// pickRead chooses a read strategy that is legal for the given mount.
func pickRead(rng *rand.Rand, mount model.MountMode) model.ReadMode {
	all := []string{
		string(model.ReadOnce), string(model.ReadOnce), string(model.ReadOnce),
		string(model.ReadPoll), string(model.ReadPoll),
		string(model.ReadWatchFile), string(model.ReadWatchFile),
		string(model.ReadWatchDir),
		string(model.ReadWatchDirFiltered), string(model.ReadWatchDirFiltered),
		string(model.ReadPollWatch),
	}
	for {
		choice := model.ReadMode(all[rng.Intn(len(all))])
		if mount == model.MountEnv {
			// Env vars have no filesystem path to watch; only startup/poll
			// semantics are meaningful (both read a frozen rendered value).
			if rng.Float64() < 0.5 {
				return model.ReadOnce
			}
			return model.ReadPoll
		}
		return choice
	}
}

// Rotate writes the v2 version of every tracked secret into the store. New
// certs get a long validity; the v1 cert's NotAfter is the rotation deadline.
func Rotate(st *store.Store, secrets []*SecretSpec, ca *certs.CA, serialCounter int64, newTTL time.Duration) (int64, time.Time, error) {
	notAfterV2 := time.Now().Add(newTTL)
	for _, s := range secrets {
		leaf, err := ca.NewLeaf(s.Name+"-v2", big.NewInt(serialCounter), time.Now().Add(-time.Minute), notAfterV2)
		if err != nil {
			return serialCounter, time.Time{}, err
		}
		serialCounter++
		mat := &store.Material{
			Version: "v2", RV: 2, CertPEM: leaf.CertPEM, KeyPEM: leaf.KeyPEM,
			EnvB64: leaf.EnvB64, Serial: leaf.Cert.SerialNumber.String(), NotAfter: notAfterV2,
		}
		st.Put(store.ObjectKey{Name: s.Name, Key: "tls.crt"}, mat)
		s.Versions["v2"] = mat
	}
	return serialCounter, notAfterV2, nil
}
