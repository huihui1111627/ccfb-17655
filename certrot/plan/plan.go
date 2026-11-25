// Package plan turns a scan result into an executable rotation plan:
// how long the old/new certificates must overlap, which containers must be
// restarted before expiry, and in what order.
package plan

import (
	"time"

	"certrot/model"
	"certrot/scan"
)

// Batch is one restart batch: a small group spread across nodes, so no two
// peers of the same service go down together.
type Batch struct {
	Index      int                `json:"index"`
	Tier       int                `json:"tier"`
	Containers []*model.Container `json:"containers"`
	DeadlineBy time.Duration      `json:"deadlineBy"` // relative to rotation start
	Label      string             `json:"label"`
}

// Plan is the full rotation recommendation.
type Plan struct {
	// MinOverlap is the minimum old/new validity overlap the rotation needs:
	// max auto-update bound plus a safety margin.
	MinOverlap            time.Duration            `json:"-"`
	MinOverlapSec         float64                  `json:"minOverlapSec"`
	RecommendedOverlap    time.Duration            `json:"-"`
	RecommendedOverlapSec float64                  `json:"recommendedOverlapSec"`
	AutoUpdateCount       int                      `json:"autoUpdateCount"`
	RestartCount          int                      `json:"restartCount"`
	Batches               []*Batch                 `json:"batches"`
	RestartList           []*model.PredictionEntry `json:"restartList"`
	Rationale             []string                 `json:"rationale"`
}

// Build creates the plan from a scan summary.
func Build(sum *scan.Summary, containers []*model.Container) *Plan {
	p := &Plan{
		AutoUpdateCount: sum.WillAutoUpdate,
		RestartCount:    sum.NeverUpdates,
		RestartList:     sum.NeverList,
	}

	maxBound := sum.BoundsP50P95Max[2]
	if maxBound == 0 {
		maxBound = 60 * time.Second
	}
	// Overlap must cover: slowest node sync + slowest app reload (already in
	// maxBound) plus operational margin (2x) for missed syncs and on-call
	// response time.
	p.MinOverlap = maxBound + 10*time.Second
	p.RecommendedOverlap = 2*maxBound + 30*time.Second
	p.MinOverlapSec = p.MinOverlap.Seconds()
	p.RecommendedOverlapSec = p.RecommendedOverlap.Seconds()

	// ---- restart batching ------------------------------------------------
	neverByID := map[string]*model.Container{}
	for _, c := range containers {
		if c.Prediction != nil && !c.Prediction.WillUpdate {
			neverByID[c.ID] = c
		}
	}
	// Preserve scan ordering (already tier -> node -> id).
	var never []*model.Container
	for _, e := range sum.NeverList {
		if c, ok := neverByID[e.ContainerID]; ok {
			never = append(never, c)
		}
	}

	const batchSize = 6
	// Round-robin across nodes inside each batch so one node/tier never loses
	// many containers simultaneously.
	byTier := map[int][]*model.Container{}
	for _, c := range never {
		byTier[c.Tier] = append(byTier[c.Tier], c)
	}
	tierLabels := map[int]string{
		0: "核心基础设施(支付/网关,优先保障,最后重启)",
		1: "中间层服务",
		2: "一般业务(最先重启,验证流程)",
	}
	idx := 0
	for tier := 2; tier >= 0; tier-- {
		group := spreadByNode(byTier[tier])
		for start := 0; start < len(group); start += batchSize {
			end := start + batchSize
			if end > len(group) {
				end = len(group)
			}
			idx++
			p.Batches = append(p.Batches, &Batch{
				Index: idx, Tier: tier, Containers: group[start:end],
				Label: tierLabels[tier],
			})
		}
	}
	// Every batch must finish before the old cert expires; critical tier gets
	// the tightest internal ordering (already last in line).
	for _, b := range p.Batches {
		b.DeadlineBy = p.RecommendedOverlap
	}

	p.Rationale = []string{
		"自动换证容器的最慢上界 = 节点同步周期(含抖动)+ 应用重读间隔,取全网最大值",
		"最小重叠期 = 最慢上界 + 10s 余量,覆盖一次错过同步周期的情况",
		"建议重叠期 = 最慢上界 × 2 + 30s,为值班介入和重启批次执行留出操作窗口",
		"必须重启的容器按 一般业务 → 中间层 → 核心基础设施 的顺序,每批 6 个且跨节点打散",
		"subPath/环境变量类故障在挂载与运行时层,改应用代码无法补救,只能重建 Pod;文件监听类故障应同时推动应用改为目录监听或定时重读",
	}
	return p
}

// spreadByNode reorders containers so consecutive entries sit on different
// nodes (round-robin by node), then keeps workload ordering within a node.
func spreadByNode(in []*model.Container) []*model.Container {
	byNode := map[string][]*model.Container{}
	var nodeOrder []string
	for _, c := range in {
		if _, ok := byNode[c.Node]; !ok {
			nodeOrder = append(nodeOrder, c.Node)
		}
		byNode[c.Node] = append(byNode[c.Node], c)
	}
	var out []*model.Container
	for {
		progressed := false
		for _, nd := range nodeOrder {
			if len(byNode[nd]) > 0 {
				out = append(out, byNode[nd][0])
				byNode[nd] = byNode[nd][1:]
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return out
}
