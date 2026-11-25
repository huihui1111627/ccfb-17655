// Package model defines the shared simulation types: cluster workloads,
// containers, mount/read modes and runtime state.
package model

import (
	"sync"
	"time"
)

// MountMode mirrors the different ways a pod exposes secret material to a
// container, as far as kubelet propagation is concerned.
type MountMode string

const (
	// MountVolume is a normal whole-volume secret/projected mount: kubelet's
	// atomic writer updates it via ..data symlink swap.
	MountVolume MountMode = "volume"
	// MountSubPath pins a single file via subPath: the bind mount stays on the
	// version rendered at container start and is never updated.
	MountSubPath MountMode = "subpath"
	// MountEnv means the certificate is injected as an environment variable,
	// rendered once at container start.
	MountEnv MountMode = "env"
)

// ReadMode is how the application inside the container consumes the cert.
type ReadMode string

const (
	ReadOnce             ReadMode = "read-once"          // parse once at startup, never again
	ReadPoll             ReadMode = "poll"               // periodic re-read on a ticker
	ReadWatchFile        ReadMode = "watch-file"         // fsnotify/inotify on the cert file path
	ReadWatchDir         ReadMode = "watch-dir"          // watch the mount directory, reload on any event
	ReadWatchDirFiltered ReadMode = "watch-dir-filtered" // watch dir, reload only when event name == cert file name
	ReadPollWatch        ReadMode = "poll+watch-dir"     // belt-and-suspenders combo: ticker plus directory watch
)

// Prediction is the static scanner's verdict for one container, produced
// before (and independently of) the live rotation.
type Prediction struct {
	WillUpdate   bool    `json:"willUpdate"`   // app will load the new cert without a restart
	DiskUpdates  bool    `json:"diskUpdates"`  // the content visible on the container's filesystem/env updates
	Layer        string  `json:"layer"`        // which layer blocks (or delivers) propagation
	Reason       string  `json:"reason"`       // human readable explanation
	BoundSeconds float64 `json:"boundSeconds"` // worst-case delay bound for auto-updating containers
}

// PredictionEntry pairs a container identity with its scan prediction, used
// by the "never updates" lists in scan output, plan and UI.
type PredictionEntry struct {
	ContainerID string `json:"containerId"`
	Workload    string `json:"workload"`
	Namespace   string `json:"namespace"`
	Node        string `json:"node"`
	Tier        int    `json:"tier"`
	Mount       string `json:"mount"`
	Read        string `json:"read"`
	Layer       string `json:"layer"`
	Reason      string `json:"reason"`
}

// CertEvent is one entry in a container's certificate lifecycle log.
type CertEvent struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"` // startup, reload, restart, expired, error
	Version string    `json:"version"`
	Serial  string    `json:"serial"`
	Detail  string    `json:"detail"`
}

// Container is one simulated container: its spec plus live runtime state.
type Container struct {
	// identity / spec
	ID         string    `json:"id"`
	PodID      string    `json:"podId"`
	Workload   string    `json:"workload"`
	Namespace  string    `json:"namespace"`
	Kind       string    `json:"kind"`
	Tier       int       `json:"tier"` // 0 = critical infra, 2 = best-effort
	Node       string    `json:"node"`
	Mount      MountMode `json:"mount"`
	Read       ReadMode  `json:"read"`
	SecretName string    `json:"secretName"`
	CertKey    string    `json:"certKey"`

	// timing knobs
	PollInterval time.Duration `json:"-"`

	// real filesystem paths (all file operations happen on disk)
	VolumeDir string `json:"-"` // kubelet volume directory (atomic-writer layout)
	MountDir  string `json:"-"` // directory the app watches in watch-dir modes
	CertPath  string `json:"-"` // path the app opens for file-based mounts
	EnvPath   string `json:"-"` // rendered env file for env mounts

	// runtime state, guarded by Mu
	Mu *sync.RWMutex `json:"-"`

	StartedAt      time.Time  `json:"startedAt"`
	RestartCount   int        `json:"restartCount"`
	LoadedVersion  string     `json:"loadedVersion"` // v1 / v2
	LoadedSerial   string     `json:"loadedSerial"`
	LoadedNotAfter time.Time  `json:"loadedNotAfter"`
	LastRead       time.Time  `json:"lastRead"`
	ReloadCount    int        `json:"reloadCount"`
	SwitchTime     *time.Time `json:"switchTime"` // first time the new cert was loaded
	Status         string     `json:"status"`     // starting, ok, expired, error

	// what an independent verifier sees on disk / in the rendered env right now
	DiskVersion   string    `json:"diskVersion"`
	DiskSerial    string    `json:"diskSerial"`
	DiskCheckedAt time.Time `json:"diskCheckedAt"`

	Events     []CertEvent `json:"events"`
	Prediction *Prediction `json:"prediction,omitempty"`
}

// AddEvent appends a lifecycle event, keeping the ring capped.
func (c *Container) AddEvent(typ, version, serial, detail string) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	c.Events = append(c.Events, CertEvent{
		Time: time.Now(), Type: typ, Version: version, Serial: serial, Detail: detail,
	})
	if len(c.Events) > 60 {
		c.Events = c.Events[len(c.Events)-60:]
	}
}

// Snapshot returns the JSON-friendly view; the prediction pointer is kept as
// is. Callers may not mutate the returned slices.
func (c *Container) Snapshot() *Container {
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	cp := *c
	cp.Events = append([]CertEvent(nil), c.Events...)
	return &cp
}

// Workload is a pod-producing controller (Deployment, StatefulSet, ...).
type Workload struct {
	ID         string       `json:"id"`
	Namespace  string       `json:"namespace"`
	Name       string       `json:"name"`
	Kind       string       `json:"kind"`
	Tier       int          `json:"tier"`
	Node       string       `json:"node"`
	Containers []*Container `json:"containers"`
}

// Point is one timeseries sample of fleet-wide certificate usage.
type Point struct {
	Time           time.Time `json:"time"`
	ElapsedSeconds float64   `json:"elapsed"`
	Total          int       `json:"total"`
	LoadedV1       int       `json:"loadedV1"`
	LoadedV2       int       `json:"loadedV2"`
	LoadedExpired  int       `json:"loadedExpired"`
	DiskV1         int       `json:"diskV1"`
	DiskV2         int       `json:"diskV2"`
	DiskUnknown    int       `json:"diskUnknown"`
}
