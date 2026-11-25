// Package app simulates the application process inside each container: it
// reads the certificate the way a real program would and tracks which
// certificate it currently holds. File watching uses fsnotify (inotify on
// Linux, FSEvents on macOS), so event behavior is measured, not scripted.
package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"certrot/certs"
	"certrot/model"
)

// Runner owns the goroutines implementing each container's read strategy.
type Runner struct {
	mu sync.RWMutex
	// serial -> version label ("v1"/"v2"), registered as secrets are created.
	versions map[string]string

	// restartPrep re-renders start-time-pinned sources (subPath / env) on a
	// container restart; injected by the simulation layer (node package).
	restartPrep func(*model.Container) error

	cancels  map[string]context.CancelFunc
	restartL sync.Map // container ID -> mutex
}

// NewRunner builds a runner. restartPrep may be nil when restarts aren't
// wired (unit tests).
func NewRunner(restartPrep func(*model.Container) error) *Runner {
	return &Runner{
		versions:    make(map[string]string),
		restartPrep: restartPrep,
		cancels:     make(map[string]context.CancelFunc),
	}
}

// RegisterMaterial teaches the runner which version label a cert serial maps
// to, so a reload can be labeled v1/v2 from the parsed certificate alone.
func (r *Runner) RegisterMaterial(serial, version string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.versions[serial] = version
}

func (r *Runner) versionOf(serial string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if v, ok := r.versions[serial]; ok {
		return v
	}
	return "unknown"
}

// VersionOfPublic exposes serial->version lookups to the independent
// verifier (which reads raw bytes off disk and parses them itself).
func (r *Runner) VersionOfPublic(serial string) string {
	return r.versionOf(serial)
}

// readCertRaw reads the bytes the app sees through its configured source.
func readCertRaw(c *model.Container) ([]byte, error) {
	if c.Mount == model.MountEnv {
		raw, err := os.ReadFile(c.EnvPath)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "TLS_CERT=") {
				return []byte(strings.TrimPrefix(line, "TLS_CERT=")), nil
			}
		}
		return nil, os.ErrNotExist
	}
	return os.ReadFile(c.CertPath)
}

// Reload performs one read-and-parse cycle and updates the container's
// loaded-certificate state. Returns true when the loaded cert changed.
func (r *Runner) Reload(c *model.Container) (changed bool, err error) {
	raw, err := readCertRaw(c)
	if err != nil {
		c.AddEvent("error", "", "", "读取失败: "+err.Error())
		c.Mu.Lock()
		c.Status = "error"
		c.Mu.Unlock()
		return false, err
	}
	cert, err := certs.ParseLeaf(raw)
	if err != nil {
		c.AddEvent("error", "", "", "解析证书失败: "+err.Error())
		return false, err
	}
	serial := cert.SerialNumber.String()
	version := r.versionOf(serial)

	c.Mu.Lock()
	c.LastRead = time.Now()
	prev := c.LoadedSerial
	c.LoadedSerial = serial
	c.LoadedVersion = version
	c.LoadedNotAfter = cert.NotAfter
	if prev != "" && prev != serial {
		changed = true
		c.ReloadCount++
		t := time.Now()
		if c.SwitchTime == nil {
			c.SwitchTime = &t
		}
	}
	if prev == "" {
		c.ReloadCount = 0
	}
	switch {
	case time.Now().After(cert.NotAfter):
		c.Status = "expired"
	default:
		c.Status = "ok"
	}
	c.Mu.Unlock()

	if changed {
		c.AddEvent("reload", version, certs.Fingerprint(cert), "应用加载了不同序列号的证书")
	}
	return changed, nil
}

// Start launches the app process for a container: initial read plus the
// goroutines implementing its read strategy.
func (r *Runner) Start(c *model.Container) {
	c.Mu.Lock()
	c.StartedAt = time.Now()
	c.Status = "starting"
	c.Mu.Unlock()

	if _, err := r.Reload(c); err == nil {
		c.AddEvent("startup", c.LoadedVersion, certsFingerprint(c), "进程启动,首次读取证书")
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	if old, ok := r.cancels[c.ID]; ok {
		old()
	}
	r.cancels[c.ID] = cancel
	r.mu.Unlock()

	switch c.Read {
	case model.ReadOnce:
		// no background activity: whatever was read at startup is it.
	case model.ReadPoll:
		go r.pollLoop(ctx, c)
	case model.ReadWatchFile:
		go r.watchLoop(ctx, c, watchFile)
	case model.ReadWatchDir:
		go r.watchLoop(ctx, c, watchDir)
	case model.ReadWatchDirFiltered:
		go r.watchLoop(ctx, c, watchDirFiltered)
	case model.ReadPollWatch:
		go r.pollLoop(ctx, c)
		go r.watchLoop(ctx, c, watchDir)
	}
}

func certsFingerprint(c *model.Container) string {
	raw, err := readCertRaw(c)
	if err != nil {
		return ""
	}
	cert, err := certs.ParseLeaf(raw)
	if err != nil {
		return ""
	}
	return certs.Fingerprint(cert)
}

// Stop cancels a container's background loops.
func (r *Runner) Stop(c *model.Container) {
	r.mu.Lock()
	cancel := r.cancels[c.ID]
	delete(r.cancels, c.ID)
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Restart models a container restart: stop the process, re-render pinned
// sources (subPath/env), then start again — which re-reads everything.
func (r *Runner) Restart(c *model.Container) error {
	lk, _ := r.restartL.LoadOrStore(c.ID, &sync.Mutex{})
	mu := lk.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	r.Stop(c)
	if r.restartPrep != nil {
		if err := r.restartPrep(c); err != nil {
			return err
		}
	}
	c.Mu.Lock()
	c.RestartCount++
	c.Mu.Unlock()
	c.AddEvent("restart", "", "", "容器重启")
	r.Start(c)
	return nil
}

func (r *Runner) pollLoop(ctx context.Context, c *model.Container) {
	interval := c.PollInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = r.Reload(c)
		}
	}
}

type watchKind int

const (
	watchFile watchKind = iota
	watchDir
	watchDirFiltered
)

// watchLoop runs one fsnotify watcher. The debounce collapses the burst of
// events that an atomic swap produces into a single reload, like real
// cert-reload libraries do.
//
// Platform note: Linux inotify and macOS kqueue disagree on symlink swaps.
// inotify pins the resolved inode, so kubelet's ..data rename produces no
// event on a file watch at all; kqueue re-resolves the path and synthesizes
// REMOVE/CREATE pairs. Production clusters run Linux, so the watch-file and
// filtered-dir strategies below enforce inotify semantics explicitly
// (identity pinning), keeping simulation results platform-independent while
// all watching is still performed by the real fsnotify backend.
func (r *Runner) watchLoop(ctx context.Context, c *model.Container, kind watchKind) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		c.AddEvent("error", "", "", "创建 watcher 失败: "+err.Error())
		return
	}
	defer w.Close()

	target := c.CertPath
	if kind != watchFile {
		target = c.MountDir
	}
	if err := w.Add(target); err != nil {
		c.AddEvent("error", "", "", "watcher.Add 失败: "+err.Error())
		return
	}

	// inotify pins the watch to the inode resolved at registration time;
	// capture that identity so path-level relinks can be distinguished from
	// genuine content writes to the same file.
	_, pinnedInfo := resolveIdentity(c.CertPath)
	// For the filtered directory watch, pin the cert's own directory entry
	// (the symlink itself), which kubelet never touches during a swap.
	pinnedLinkInfo := lstatOrNil(c.CertPath)
	pinnedLinkTarget, _ := os.Readlink(c.CertPath)

	debounce := 150 * time.Millisecond
	var timer *time.Timer
	fire := make(chan struct{}, 1)
	arm := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(debounce, func() {
			select {
			case fire <- struct{}{}:
			default:
			}
		})
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if kind == watchFile {
				// inotify semantics: reload only for a content event on the
				// SAME inode that was registered. A ..data swap changes the
				// resolved identity (kqueue's synthetic REMOVE/CREATE) and the
				// later GC only deletes the old inode (IN_IGNORED on Linux) —
				// neither is a content write, so neither triggers a reload.
				if ev.Op&(fsnotify.Write|fsnotify.Chmod) == 0 {
					continue
				}
				_, curInfo := resolveIdentity(c.CertPath)
				if curInfo == nil || pinnedInfo == nil || !os.SameFile(pinnedInfo, curInfo) {
					continue
				}
			}
			if kind == watchDirFiltered {
				// Common real-world bug: the app only reacts to events whose
				// name is the cert file. On Linux a kubelet swap emits events
				// for the timestamped directory and ..data, never tls.crt, so
				// the filter drops everything. To stay faithful on macOS too,
				// additionally require the cert's own directory entry to have
				// actually changed (it does not in the atomic-writer layout).
				if baseName(ev.Name) != baseName(c.CertKey) {
					continue
				}
				curLink := lstatOrNil(c.CertPath)
				curTarget, _ := os.Readlink(c.CertPath)
				if sameLinkEntry(pinnedLinkInfo, curLink) && curTarget == pinnedLinkTarget {
					continue
				}
				// A genuine change of the cert entry: re-pin and reload.
				pinnedLinkInfo = curLink
				pinnedLinkTarget = curTarget
			}
			arm()
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			c.AddEvent("error", "", "", "watcher 错误: "+err.Error())
		case <-fire:
			_, _ = r.Reload(c)
		}
	}
}

// resolveIdentity follows symlinks and returns the resolved path plus the
// stat info of the final target.
func resolveIdentity(path string) (string, os.FileInfo) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return resolved, nil
	}
	return resolved, info
}

func lstatOrNil(path string) os.FileInfo {
	info, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	return info
}

func sameLinkEntry(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	return os.SameFile(a, b)
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
