// Package sim is the simulation orchestrator: it wires the apiserver store,
// kubelet nodes, container app processes, an independent disk verifier and
// a timeseries sampler together, drives the rotation, and produces the
// prediction-vs-reality comparison report.
package sim

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"certrot/app"
	"certrot/certs"
	"certrot/cluster"
	"certrot/model"
	"certrot/plan"
	"certrot/scan"
	"certrot/store"
)

// Phase labels the simulation lifecycle.
type Phase string

const (
	PhaseInit    Phase = "init"
	PhaseRunning Phase = "running"
	PhaseRotated Phase = "rotated"
	PhaseExpired Phase = "expired"
	PhaseStopped Phase = "stopped"
)

// Config is the simulation configuration.
type Config struct {
	DataDir       string
	WorkloadCount int
	NodeCount     int
	OldCertTTL    time.Duration // how long after start the v1 cert expires
	NewCertTTL    time.Duration
	SampleEvery   time.Duration
	VerifyEvery   time.Duration
	Seed          int64
	// NodeSyncBase overrides the default kubelet sync period (tests use small
	// values); 0 keeps the package default.
	NodeSyncBase time.Duration
}

// RotationInfo records when the rotation happened and both cert windows.
type RotationInfo struct {
	At          time.Time `json:"at"`
	Elapsed     float64   `json:"elapsedSeconds"`
	OldNotAfter time.Time `json:"oldNotAfter"`
	NewNotAfter time.Time `json:"newNotAfter"`
	Performed   bool      `json:"performed"`
}

// ContainerReport is the per-container prediction vs actual comparison row.
type ContainerReport struct {
	ContainerID     string   `json:"containerId"`
	Workload        string   `json:"workload"`
	Namespace       string   `json:"namespace"`
	Node            string   `json:"node"`
	Tier            int      `json:"tier"`
	Mount           string   `json:"mount"`
	Read            string   `json:"read"`
	PredictedUpdate bool     `json:"predictedUpdate"`
	PredictedLayer  string   `json:"predictedLayer"`
	ActualUpdated   bool     `json:"actualUpdated"`
	SwitchElapsed   *float64 `json:"switchElapsedSeconds"`
	BoundSeconds    float64  `json:"boundSeconds"`
	WithinBound     *bool    `json:"withinBound"`
	Verdict         string   `json:"verdict"` // consistent, missed, false-alarm, over-bound
	Restarted       bool     `json:"restarted"`
}

// Report is the full prediction-vs-reality comparison.
type Report struct {
	GeneratedAt       time.Time          `json:"generatedAt"`
	Total             int                `json:"total"`
	Consistent        int                `json:"consistent"`
	Missed            int                `json:"missed"` // predicted auto-update but never happened
	FalseAlarm        int                `json:"falseAlarm"`
	OverBound         int                `json:"overBound"`
	RestartHealed     int                `json:"restartHealed"` // predicted never; switched only because of a restart
	Rows              []*ContainerReport `json:"rows"`
	NeverStillStale   []*ContainerReport `json:"neverStillStale"` // the "漏网" check
	PredictedNeverCnt int                `json:"predictedNeverCnt"`
	ActualNeverCnt    int                `json:"actualNeverCnt"`
}

// Snapshot is the full UI/API state.
type Snapshot struct {
	Phase      Phase                    `json:"phase"`
	StartedAt  time.Time                `json:"startedAt"`
	Now        time.Time                `json:"now"`
	Rotation   *RotationInfo            `json:"rotation"`
	Workloads  []*model.Workload        `json:"workloads"`
	Containers []*model.Container       `json:"containers"`
	Series     []model.Point            `json:"series"`
	NodeLogs   map[string][]NodeLogView `json:"nodeLogs"`
	Scan       *scan.Summary            `json:"scan"`
	Plan       *plan.Plan               `json:"plan"`
	Report     *Report                  `json:"report"`
	Config     ConfigView               `json:"config"`
}

// NodeLogView is a JSON-friendly node log entry.
type NodeLogView struct {
	Time   time.Time `json:"time"`
	Node   string    `json:"node"`
	Secret string    `json:"secret"`
	RV     int64     `json:"rv"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

// ConfigView surfaces timing parameters for the UI.
type ConfigView struct {
	WorkloadCount    int                `json:"workloadCount"`
	NodeCount        int                `json:"nodeCount"`
	OldCertTTLSec    float64            `json:"oldCertTTLSec"`
	SampleEverySec   float64            `json:"sampleEverySec"`
	VerifyEverySec   float64            `json:"verifyEverySec"`
	NodeIntervalsSec map[string]float64 `json:"nodeIntervalsSec"`
}

// Sim is the running simulation.
type Sim struct {
	cfg Config

	ca      *certs.CA
	st      *store.Store
	build   *cluster.BuildResult
	runner  *app.Runner
	scanSum *scan.Summary
	pl      *plan.Plan

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.RWMutex
	phase     Phase
	startedAt time.Time
	rotation  *RotationInfo
	series    []model.Point
	report    *Report

	serialCounter int64
}

// New builds the fleet and runs the static scan, but starts nothing yet.
func New(cfg Config) (*Sim, error) {
	if err := os.RemoveAll(cfg.DataDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewSource(cfg.Seed))
	ca, err := certs.NewCA(10 * 365 * 24 * time.Hour)
	if err != nil {
		return nil, err
	}
	st := store.New()
	b, err := cluster.Build(cluster.Config{
		WorkloadCount: cfg.WorkloadCount,
		NodeCount:     cfg.NodeCount,
		DataDir:       cfg.DataDir,
		OldCertTTL:    cfg.OldCertTTL,
		Seed:          cfg.Seed,
		NodeSyncBase:  cfg.NodeSyncBase,
	}, ca, st, rng)
	if err != nil {
		return nil, err
	}

	s := &Sim{
		cfg:           cfg,
		ca:            ca,
		st:            st,
		build:         b,
		serialCounter: 2000,
		phase:         PhaseInit,
	}
	s.runner = app.NewRunner(s.restartPrep)
	for serial, v := range b.SerialVersion {
		s.runner.RegisterMaterial(serial, v)
	}
	// Static scan happens before any rotation, exactly like a fleet audit.
	s.scanSum = scan.Run(b.Containers, b.Nodes)
	s.pl = plan.Build(s.scanSum, b.Containers)
	return s, nil
}

// Start launches node sync loops, all container apps, verifier and sampler.
func (s *Sim) Start() {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.mu.Lock()
	s.startedAt = time.Now()
	s.phase = PhaseRunning
	s.mu.Unlock()

	// Bootstrap every node synchronously so whole-volume mounts are rendered
	// before any app process takes its first (possibly one-shot) read.
	for _, n := range s.build.Nodes {
		n.Sync(s.build.Containers)
	}
	// Node periodic sync loops. Their first tick now no-ops until the store
	// gets a new resource version.
	for _, n := range s.build.Nodes {
		n := n
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			n.Run(s.ctx, s.build.Containers)
		}()
	}
	// Container app processes.
	for _, c := range s.build.Containers {
		s.runner.Start(c)
	}

	s.wg.Add(3)
	go s.verifierLoop()
	go s.samplerLoop()
	go s.expiryLoop()
}

func (s *Sim) restartPrep(c *model.Container) error {
	for _, n := range s.build.Nodes {
		if n.Name == c.Node {
			return n.PrepareRestart(c)
		}
	}
	return fmt.Errorf("node %s not found", c.Node)
}

// Rotate performs the secret rotation: new cert versions land in the store;
// nodes pick them up on their next sync.
func (s *Sim) Rotate() error {
	s.mu.Lock()
	if s.rotation != nil {
		s.mu.Unlock()
		return fmt.Errorf("rotation already performed")
	}
	s.mu.Unlock()

	cnt, newNotAfter, err := cluster.Rotate(s.st, s.build.Secrets, s.ca, s.serialCounter, cfgTTL(s.cfg.NewCertTTL))
	if err != nil {
		return err
	}
	s.serialCounter = cnt
	for _, sec := range s.build.Secrets {
		v2 := sec.Versions["v2"]
		s.runner.RegisterMaterial(v2.Serial, "v2")
	}
	s.mu.Lock()
	oldNotAfter := s.build.Secrets[0].NotAfter
	s.rotation = &RotationInfo{
		At: time.Now(), Elapsed: time.Since(s.startedAt).Seconds(),
		OldNotAfter: oldNotAfter, NewNotAfter: newNotAfter, Performed: true,
	}
	s.phase = PhaseRotated
	s.mu.Unlock()
	return nil
}

func cfgTTL(d time.Duration) time.Duration {
	if d == 0 {
		return 365 * 24 * time.Hour
	}
	return d
}

// Restart restarts one container through the app runner (pinned sources get
// re-rendered first).
func (s *Sim) Restart(containerID string) error {
	for _, c := range s.build.Containers {
		if c.ID == containerID {
			return s.runner.Restart(c)
		}
	}
	return fmt.Errorf("container %s not found", containerID)
}

// RestartBatch executes one plan batch by index (1-based).
func (s *Sim) RestartBatch(batchIndex int) ([]string, error) {
	if batchIndex < 1 || batchIndex > len(s.pl.Batches) {
		return nil, fmt.Errorf("batch %d out of range (1..%d)", batchIndex, len(s.pl.Batches))
	}
	b := s.pl.Batches[batchIndex-1]
	var ids []string
	for _, c := range b.Containers {
		if err := s.runner.Restart(c); err != nil {
			return ids, err
		}
		ids = append(ids, c.ID)
	}
	return ids, nil
}

// ---- background loops -----------------------------------------------------

func (s *Sim) verifierLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.VerifyEvery)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.verifyOnce()
		}
	}
}

// verifyOnce is the independent verifier: it parses the cert actually
// visible on each container's disk/env, with no reference to what the app
// thinks it loaded.
func (s *Sim) verifyOnce() {
	for _, c := range s.build.Containers {
		var raw []byte
		var err error
		if c.Mount == model.MountEnv {
			raw, err = os.ReadFile(c.EnvPath)
			if err == nil {
				raw = extractEnvCert(raw)
			}
		} else {
			raw, err = os.ReadFile(c.CertPath)
		}
		c.Mu.Lock()
		c.DiskCheckedAt = time.Now()
		if err != nil {
			c.DiskVersion = "unknown"
			c.DiskSerial = ""
			c.Mu.Unlock()
			continue
		}
		cert, perr := certs.ParseLeaf(raw)
		if perr != nil {
			c.DiskVersion = "unknown"
			c.DiskSerial = ""
		} else {
			c.DiskSerial = cert.SerialNumber.String()
			c.DiskVersion = s.runner.VersionOfPublic(c.DiskSerial)
		}
		c.Mu.Unlock()
	}
}

func extractEnvCert(raw []byte) []byte {
	for _, line := range splitLines(string(raw)) {
		if len(line) > 9 && line[:9] == "TLS_CERT=" {
			return []byte(line[9:])
		}
	}
	return raw
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func (s *Sim) samplerLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.SampleEvery)
	defer t.Stop()
	// one immediate sample so the chart has a t=0 point
	s.sampleOnce()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.sampleOnce()
		}
	}
}

func (s *Sim) sampleOnce() {
	p := model.Point{Time: time.Now(), Total: len(s.build.Containers)}
	p.ElapsedSeconds = p.Time.Sub(s.startedAt).Seconds()
	now := time.Now()
	for _, c := range s.build.Containers {
		c.Mu.RLock()
		switch c.LoadedVersion {
		case "v2":
			p.LoadedV2++
		case "v1":
			p.LoadedV1++
		}
		if !c.LoadedNotAfter.IsZero() && now.After(c.LoadedNotAfter) {
			p.LoadedExpired++
		}
		switch c.DiskVersion {
		case "v1":
			p.DiskV1++
		case "v2":
			p.DiskV2++
		default:
			p.DiskUnknown++
		}
		c.Mu.RUnlock()
	}
	s.mu.Lock()
	s.series = append(s.series, p)
	if len(s.series) > 4000 {
		s.series = s.series[len(s.series)-4000:]
	}
	s.mu.Unlock()
}

func (s *Sim) expiryLoop() {
	defer s.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.markExpired(now)
		}
	}
}

func (s *Sim) markExpired(now time.Time) {
	s.mu.RLock()
	rot := s.rotation
	s.mu.RUnlock()
	anyExpired := false
	for _, c := range s.build.Containers {
		c.Mu.Lock()
		if !c.LoadedNotAfter.IsZero() && now.After(c.LoadedNotAfter) && c.Status != "expired" {
			c.Status = "expired"
			c.Events = append(c.Events, model.CertEvent{
				Time: now, Type: "expired", Version: c.LoadedVersion,
				Serial: c.LoadedSerial, Detail: "进程持有的证书已到期",
			})
			anyExpired = true
		}
		c.Mu.Unlock()
	}
	if rot != nil && now.After(rot.OldNotAfter) {
		s.mu.Lock()
		if s.phase == PhaseRotated {
			s.phase = PhaseExpired
		}
		s.mu.Unlock()
	}
	_ = anyExpired
}

// ---- report ---------------------------------------------------------------

// BuildReport compares every static prediction against measured behavior.
// Call after enough simulated time has elapsed for auto-updaters to settle.
func (s *Sim) BuildReport() *Report {
	s.mu.RLock()
	rot := s.rotation
	s.mu.RUnlock()
	r := &Report{Total: len(s.build.Containers), Rows: []*ContainerReport{}}

	for _, c := range s.build.Containers {
		c.Mu.RLock()
		actualUpdated := c.LoadedVersion == "v2"
		var elapsed *float64
		if c.SwitchTime != nil && rot != nil {
			v := c.SwitchTime.Sub(rot.At).Seconds()
			elapsed = &v
		}
		pred := c.Prediction
		restarted := c.RestartCount > 0
		c.Mu.RUnlock()

		row := &ContainerReport{
			ContainerID: c.ID, Workload: c.Workload, Namespace: c.Namespace,
			Node: c.Node, Tier: c.Tier, Mount: string(c.Mount), Read: string(c.Read),
			ActualUpdated: actualUpdated, SwitchElapsed: elapsed, Restarted: restarted,
		}
		if pred != nil {
			row.PredictedUpdate = pred.WillUpdate
			row.PredictedLayer = pred.Layer
			row.BoundSeconds = pred.BoundSeconds
		}
		switch {
		case row.PredictedUpdate && actualUpdated && !restarted:
			if elapsed != nil && *elapsed > row.BoundSeconds {
				row.Verdict = "over-bound"
				r.OverBound++
			} else {
				row.Verdict = "consistent"
				r.Consistent++
			}
			if elapsed != nil {
				ok := *elapsed <= row.BoundSeconds
				row.WithinBound = &ok
			}
		case !row.PredictedUpdate && !actualUpdated:
			row.Verdict = "consistent"
			r.Consistent++
			r.PredictedNeverCnt++
			r.ActualNeverCnt++
			r.NeverStillStale = append(r.NeverStillStale, row)
		case row.PredictedUpdate && !actualUpdated:
			// The dangerous case: scanner said it would heal itself, it didn't.
			row.Verdict = "missed"
			r.Missed++
		case !row.PredictedUpdate && actualUpdated && restarted:
			// Scanner was right that it never self-heals; the planned restart
			// is what loaded v2 — the rotation plan working as designed.
			row.Verdict = "restarted"
			r.RestartHealed++
			r.PredictedNeverCnt++
		default:
			// Predicted never, updated without any restart: scanner missed a
			// propagation path.
			row.Verdict = "false-alarm"
			r.FalseAlarm++
		}
		r.Rows = append(r.Rows, row)
	}
	r.GeneratedAt = time.Now()
	s.mu.Lock()
	s.report = r
	s.mu.Unlock()
	return r
}

// ---- snapshots ------------------------------------------------------------

// Snapshot assembles the full external state view.
func (s *Sim) Snapshot() *Snapshot {
	s.mu.RLock()
	phase := s.phase
	started := s.startedAt
	var rotCopy *RotationInfo
	if s.rotation != nil {
		v := *s.rotation
		rotCopy = &v
	}
	series := append([]model.Point(nil), s.series...)
	rep := s.report
	s.mu.RUnlock()

	containers := make([]*model.Container, 0, len(s.build.Containers))
	for _, c := range s.build.Containers {
		containers = append(containers, c.Snapshot())
	}
	logs := map[string][]NodeLogView{}
	intervals := map[string]float64{}
	for _, n := range s.build.Nodes {
		intervals[n.Name] = n.SyncInterval.Seconds()
		for _, e := range n.Log() {
			logs[n.Name] = append(logs[n.Name], NodeLogView{
				Time: e.Time, Node: e.Node, Secret: e.Secret, RV: e.RV,
				Action: e.Action, Detail: e.Detail,
			})
		}
	}
	return &Snapshot{
		Phase: phase, StartedAt: started, Now: time.Now(), Rotation: rotCopy,
		Workloads: s.build.Workloads, Containers: containers, Series: series,
		NodeLogs: logs, Scan: s.scanSum, Plan: s.pl, Report: rep,
		Config: ConfigView{
			WorkloadCount: s.cfg.WorkloadCount, NodeCount: s.cfg.NodeCount,
			OldCertTTLSec:    s.cfg.OldCertTTL.Seconds(),
			SampleEverySec:   s.cfg.SampleEvery.Seconds(),
			VerifyEverySec:   s.cfg.VerifyEvery.Seconds(),
			NodeIntervalsSec: intervals,
		},
	}
}

// Stop ends all background activity.
func (s *Sim) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	for _, c := range s.build.Containers {
		s.runner.Stop(c)
	}
	s.wg.Wait()
	s.mu.Lock()
	s.phase = PhaseStopped
	s.mu.Unlock()
}

// Plan and Scan accessors.
func (s *Sim) Plan() *plan.Plan            { return s.pl }
func (s *Sim) Scan() *scan.Summary         { return s.scanSum }
func (s *Sim) Build() *cluster.BuildResult { return s.build }
