// Package node simulates a kubelet node: the periodic apiserver sync and the
// on-disk secret/projected volume update mechanism (atomic writer), plus
// subPath bind mounts and environment-variable injection.
//
// Every file operation is real: the layout under Root is the same one a real
// kubelet produces — timestamped directories, per-file symlinks through
// ..data, and an atomic rename that swaps the ..data symlink.
package node

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"certrot/model"
	"certrot/store"
)

// LogEntry is one node-level sync observation.
type LogEntry struct {
	Time   time.Time `json:"time"`
	Node   string    `json:"node"`
	Secret string    `json:"secret"`
	RV     int64     `json:"rv"`
	Action string    `json:"action"` // volume-render, subpath-render, env-render, skip
	Detail string    `json:"detail"`
}

// Node is one simulated kubelet.
type Node struct {
	Name         string
	Root         string
	Store        *store.Store
	SyncInterval time.Duration

	mu sync.Mutex
	// lastRV tracks the resource version last rendered per container; kubelet
	// only re-renders a volume when the object's resource version changed.
	lastRV map[string]int64
	log    []LogEntry
	rng    *rand.Rand
}

// New constructs a node with its on-disk directory layout. The passed rng is
// only consumed at construction to derive a private, per-node random source;
// kubelet sync loops run concurrently and math/rand.Rand is not safe for
// shared use, so each node keeps its own.
func New(name, root string, st *store.Store, syncInterval time.Duration, rng *rand.Rand) (*Node, error) {
	n := &Node{
		Name:         name,
		Root:         root,
		Store:        st,
		SyncInterval: syncInterval,
		lastRV:       make(map[string]int64),
	}
	var seed int64
	if rng != nil {
		seed = rng.Int63()
	}
	n.rng = rand.New(rand.NewSource(seed))
	for _, sub := range []string{"volumes", "subpaths", "env"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// Log returns a copy of the recent node log.
func (n *Node) Log() []LogEntry {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]LogEntry(nil), n.log...)
}

// addLog appends to the node log. Callers that already hold n.mu must use
// addLogLocked instead — Go's mutex is not reentrant.
func (n *Node) addLog(c *model.Container, rv int64, action, detail string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.addLogLocked(c, rv, action, detail)
}

func (n *Node) addLogLocked(c *model.Container, rv int64, action, detail string) {
	n.log = append(n.log, LogEntry{
		Time: time.Now(), Node: n.Name, Secret: c.SecretName, RV: rv, Action: action, Detail: detail,
	})
	if len(n.log) > 200 {
		n.log = n.log[len(n.log)-200:]
	}
}

func (n *Node) objectKey(c *model.Container) store.ObjectKey {
	return store.ObjectKey{Name: c.SecretName, Key: c.CertKey}
}

// PreparePaths creates the container's mount paths according to its mount
// mode and performs the first render (equivalent to pod startup).
func (n *Node) PreparePaths(c *model.Container) error {
	volDir := filepath.Join(n.Root, "volumes", c.ID)
	subDir := filepath.Join(n.Root, "subpaths", c.ID)
	envPath := filepath.Join(n.Root, "env", c.ID+".env")

	switch c.Mount {
	case model.MountVolume:
		if err := os.MkdirAll(volDir, 0o755); err != nil {
			return err
		}
		c.VolumeDir = volDir
		c.MountDir = volDir
		c.CertPath = filepath.Join(volDir, c.CertKey)
	case model.MountSubPath:
		if err := os.MkdirAll(subDir, 0o755); err != nil {
			return err
		}
		c.VolumeDir = filepath.Join(n.Root, "volumes", c.ID)
		c.MountDir = subDir
		c.CertPath = filepath.Join(subDir, c.CertKey)
		// subPath: rendered once from the current object, then pinned.
		mat := n.Store.Current(n.objectKey(c))
		if mat == nil {
			return fmt.Errorf("node %s: secret %s missing for container %s", n.Name, c.SecretName, c.ID)
		}
		if err := writeReplacing(c.CertPath, mat.CertPEM, 0o444); err != nil {
			return err
		}
		n.lastRV[c.ID] = mat.RV
		n.addLog(c, mat.RV, "subpath-render", "启动时渲染,之后不再更新")
	case model.MountEnv:
		if err := os.MkdirAll(filepath.Dir(envPath), 0o755); err != nil {
			return err
		}
		c.EnvPath = envPath
		mat := n.Store.Current(n.objectKey(c))
		if mat == nil {
			return fmt.Errorf("node %s: secret %s missing for container %s", n.Name, c.SecretName, c.ID)
		}
		if err := n.writeEnv(c, mat); err != nil {
			return err
		}
		n.lastRV[c.ID] = mat.RV
		n.addLog(c, mat.RV, "env-render", "启动时注入环境变量")
	}
	return nil
}

// PrepareRestart re-renders the start-time-pinned sources when a container
// restarts. Whole-volume mounts intentionally do nothing here: kubelet keeps
// the volume across a container restart and the app simply sees the current
// ..data target on its next open().
func (n *Node) PrepareRestart(c *model.Container) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	mat := n.Store.Current(n.objectKey(c))
	if mat == nil {
		return fmt.Errorf("secret %s vanished", c.SecretName)
	}
	switch c.Mount {
	case model.MountSubPath:
		if err := writeReplacing(c.CertPath, mat.CertPEM, 0o444); err != nil {
			return err
		}
		n.lastRV[c.ID] = mat.RV
		n.addLogLocked(c, mat.RV, "subpath-render", "容器重启,重新建立 subPath 绑定")
	case model.MountEnv:
		if err := n.writeEnv(c, mat); err != nil {
			return err
		}
		n.lastRV[c.ID] = mat.RV
		n.addLogLocked(c, mat.RV, "env-render", "容器重启,重新注入环境变量")
	default:
		n.addLogLocked(c, mat.RV, "skip", "整卷挂载,重启无需重新渲染")
	}
	return nil
}

func (n *Node) writeEnv(c *model.Container, mat *store.Material) error {
	content := fmt.Sprintf("TLS_CERT=%s\nTLS_CERT_SERIAL=%s\n", mat.EnvB64, mat.Serial)
	return writeReplacing(c.EnvPath, []byte(content), 0o444)
}

// writeReplacing writes data to path via a temp file + rename so the target
// path is never observed half-written.
func writeReplacing(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// renderVolumeAtomic implements kubelet's atomic writer:
//  1. write a fresh timestamped directory (read-only files),
//  2. point a temp ..data_tmp symlink at it,
//  3. atomically rename ..data_tmp over ..data,
//  4. garbage-collect superseded timestamped directories.
//
// The user-visible file (tls.crt) is itself a symlink to ..data/tls.crt and
// is never touched during updates.
func (n *Node) renderVolumeAtomic(c *model.Container, mat *store.Material) error {
	vol := c.VolumeDir
	ts := time.Now().UTC().Format("2006_01_02_15_04_05.000000000") + fmt.Sprintf(".rv%d", mat.RV)
	newDirName := ".." + ts
	newDir := filepath.Join(vol, newDirName)
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(newDir, c.CertKey), mat.CertPEM, 0o444); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(newDir, "tls.key"), mat.KeyPEM, 0o400); err != nil {
		return err
	}

	// First render: create the stable per-file symlinks.
	leaf := filepath.Join(vol, c.CertKey)
	if _, err := os.Lstat(leaf); os.IsNotExist(err) {
		if err := os.Symlink(filepath.Join("..data", c.CertKey), leaf); err != nil {
			return err
		}
	}

	tmpLink := filepath.Join(vol, "..data_tmp")
	_ = os.Remove(tmpLink) // leftover from a crashed render
	if err := os.Symlink(newDirName, tmpLink); err != nil {
		return err
	}
	if err := os.Rename(tmpLink, filepath.Join(vol, "..data")); err != nil {
		return err
	}

	// GC: keep only the timestamped directory currently referenced by ..data.
	entries, _ := os.ReadDir(vol)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "..") || name == "..data" || name == "..data_tmp" || name == newDirName {
			continue
		}
		_ = os.RemoveAll(filepath.Join(vol, name))
	}
	return nil
}

// Sync is one kubelet sync tick: whole-volume mounts are re-rendered when the
// object changed; subPath and env sources are deliberately untouched.
func (n *Node) Sync(containers []*model.Container) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range containers {
		if c.Node != n.Name {
			continue
		}
		mat := n.Store.Current(n.objectKey(c))
		if mat == nil {
			continue
		}
		if mat.RV == n.lastRV[c.ID] {
			continue
		}
		switch c.Mount {
		case model.MountVolume:
			if err := n.renderVolumeAtomic(c, mat); err != nil {
				n.addLogLocked(c, mat.RV, "error", err.Error())
				continue
			}
			n.addLogLocked(c, mat.RV, "volume-render",
				"原子切换 ..data 指向新时间戳目录 (整目录替换,文件路径不变、底层 inode 已换)")
		case model.MountSubPath:
			// This is the real kubelet behavior: subPath mounts are not
			// propagated. The object changed on the apiserver, the container's
			// bind-mounted file stays on the old version.
			n.addLogLocked(c, mat.RV, "skip", "对象已更新,但 subPath 挂载不传播变更")
		case model.MountEnv:
			n.addLogLocked(c, mat.RV, "skip", "对象已更新,但环境变量只在启动时注入")
		}
		n.lastRV[c.ID] = mat.RV
	}
}

// Run starts the periodic sync loop until ctx is canceled. Sleeps jitter by
// ±20% like real nodes do not all tick in lockstep.
func (n *Node) Run(ctx context.Context, containers []*model.Container) {
	// Bootstrap render so volumes exist before any app starts.
	n.Sync(containers)
	for {
		jitter := time.Duration(float64(n.SyncInterval) * (0.8 + 0.4*n.rng.Float64()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
			n.Sync(containers)
		}
	}
}
