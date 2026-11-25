// Package scan is the static pre-rotation scanner: given a container spec
// (mount mode + read mode) and its node's sync period, it predicts whether
// the container will pick up a rotated certificate without a restart, how
// long the worst case takes, and — if it never will — which layer is at
// fault. No runtime state is consulted; this is the "audit the cluster"
// view before any rotation happens.
package scan

import (
	"sort"
	"time"

	"certrot/model"
	"certrot/node"
)

// Summary aggregates the fleet-level scan result.
type Summary struct {
	Total              int                      `json:"total"`
	WillAutoUpdate     int                      `json:"willAutoUpdate"`
	NeverUpdates       int                      `json:"neverUpdates"`
	ByLayer            map[string]int           `json:"byLayer"`
	ByMountRead        map[string]int           `json:"byMountRead"`
	BoundsP50P95Max    [3]time.Duration         `json:"-"`
	BoundsP50P95MaxSec [3]float64               `json:"boundsP50P95MaxSec"`
	Containers         []*model.Container       `json:"containers"`
	NeverList          []*model.PredictionEntry `json:"neverList"`
}

// Predict computes the prediction for one container.
func Predict(c *model.Container, nodes []*node.Node) *model.Prediction {
	sync := syncIntervalFor(c.Node, nodes)
	// node.Run sleeps interval*(0.8..1.2); the worst-case disk delay is the
	// top of that jitter band.
	worstDisk := time.Duration(float64(sync) * 1.2)

	switch c.Mount {
	case model.MountEnv:
		return &model.Prediction{
			WillUpdate: false, DiskUpdates: false,
			Layer: "容器运行时/环境变量",
			Reason: "证书经环境变量注入,环境变量只在容器启动时由容器运行时渲染一次;" +
				"后续 Secret 即使更新,进程内变量也不会变化,必须重启容器",
		}
	case model.MountSubPath:
		return &model.Prediction{
			WillUpdate: false, DiskUpdates: false,
			Layer: "kubelet 挂载层/subPath",
			Reason: "subPath 挂载在容器启动时把当时版本的单个文件 bind 进挂载命名空间," +
				"kubelet 的原子写入器只更新整卷目录,不传播 subPath 绑定,必须重建 Pod/重启容器",
		}
	}

	// Whole-volume mount: the disk view DOES update within one node sync.
	switch c.Read {
	case model.ReadOnce:
		return &model.Prediction{
			WillUpdate: false, DiskUpdates: true,
			Layer: "应用层/只读一次",
			Reason: "挂载目录会在节点同步后切换到新证书,但应用只在启动时读取一次," +
				"进程内存里一直是旧证书,必须重启进程",
		}
	case model.ReadWatchFile:
		return &model.Prediction{
			WillUpdate: false, DiskUpdates: true,
			Layer: "应用层/文件监听",
			Reason: "应用监听 tls.crt 路径,但 kubelet 更新时只原子替换 ..data 符号链接," +
				"文件路径本身无事件(inotify 监视的仍是旧时间戳目录的 inode),监听永远不触发,必须重启",
		}
	case model.ReadWatchDirFiltered:
		return &model.Prediction{
			WillUpdate: false, DiskUpdates: true,
			Layer: "应用层/目录事件过滤",
			Reason: "应用虽监听了挂载目录,但只接受事件名等于 tls.crt 的事件;" +
				"符号链接切换产生的是时间戳目录的 CREATE 事件,被过滤器丢弃,等于监听不到,必须重启",
		}
	case model.ReadPoll:
		bound := worstDisk + c.PollInterval
		return &model.Prediction{
			WillUpdate: true, DiskUpdates: true, Layer: "",
			Reason:       "节点同步切换 ..data 后,下一次定时重读会打开新目录读到新证书",
			BoundSeconds: bound.Seconds(),
		}
	case model.ReadWatchDir:
		bound := worstDisk + time.Second // swap event + debounce
		return &model.Prediction{
			WillUpdate: true, DiskUpdates: true, Layer: "",
			Reason:       "目录监听能收到 ..data 原子切换产生的事件,触发重读后拿到新证书",
			BoundSeconds: bound.Seconds(),
		}
	case model.ReadPollWatch:
		bound := worstDisk + time.Second
		return &model.Prediction{
			WillUpdate: true, DiskUpdates: true, Layer: "",
			Reason:       "目录监听与定时重读双重保障,任一机制先触发即完成换证",
			BoundSeconds: bound.Seconds(),
		}
	}
	return &model.Prediction{WillUpdate: false, Layer: "未知", Reason: "未识别的读取方式"}
}

func syncIntervalFor(nodeName string, nodes []*node.Node) time.Duration {
	for _, n := range nodes {
		if n.Name == nodeName {
			return n.SyncInterval
		}
	}
	return 30 * time.Second
}

// Run scans every container and attaches predictions.
func Run(containers []*model.Container, nodes []*node.Node) *Summary {
	sum := &Summary{
		Total:       len(containers),
		ByLayer:     map[string]int{},
		ByMountRead: map[string]int{},
	}
	var bounds []time.Duration
	type neverEntry struct {
		c *model.Container
		p *model.Prediction
	}
	var nevers []neverEntry

	for _, c := range containers {
		p := Predict(c, nodes)
		c.Prediction = p
		sum.ByMountRead[string(c.Mount)+" / "+string(c.Read)]++
		if p.WillUpdate {
			sum.WillAutoUpdate++
			bounds = append(bounds, time.Duration(p.BoundSeconds*float64(time.Second)))
		} else {
			sum.NeverUpdates++
			sum.ByLayer[p.Layer]++
			nevers = append(nevers, neverEntry{c, p})
		}
	}

	sort.Slice(bounds, func(i, j int) bool { return bounds[i] < bounds[j] })
	if len(bounds) > 0 {
		pick := func(q float64) time.Duration {
			idx := int(float64(len(bounds)-1) * q)
			return bounds[idx]
		}
		sum.BoundsP50P95Max = [3]time.Duration{pick(0.5), pick(0.95), bounds[len(bounds)-1]}
		for i, d := range sum.BoundsP50P95Max {
			sum.BoundsP50P95MaxSec[i] = d.Seconds()
		}
	}

	sort.Slice(nevers, func(i, j int) bool {
		if nevers[i].c.Tier != nevers[j].c.Tier {
			return nevers[i].c.Tier < nevers[j].c.Tier // critical first
		}
		if nevers[i].c.Node != nevers[j].c.Node {
			return nevers[i].c.Node < nevers[j].c.Node
		}
		return nevers[i].c.ID < nevers[j].c.ID
	})
	for _, ne := range nevers {
		sum.NeverList = append(sum.NeverList, &model.PredictionEntry{
			ContainerID: ne.c.ID, Workload: ne.c.Workload, Namespace: ne.c.Namespace,
			Node: ne.c.Node, Tier: ne.c.Tier, Mount: string(ne.c.Mount), Read: string(ne.c.Read),
			Layer: ne.p.Layer, Reason: ne.p.Reason,
		})
	}
	sum.Containers = containers
	return sum
}
