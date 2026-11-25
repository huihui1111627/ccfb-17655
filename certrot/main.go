// Command certrot runs the certificate-rotation simulation.
//
// Default mode serves the dashboard (HTTP API + embedded UI). The "demo"
// subcommand runs a full headless scenario — rotate, measure every
// container's actual switch time, compare against the static scan, restart
// the never-updating containers in plan batches, and emit a JSON report.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"certrot/sim"
	"certrot/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "demo" {
		runDemo(os.Args[2:])
		return
	}
	runServer(os.Args[1:])
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "HTTP 监听地址")
	cfg, _, _ := commonFlagsWith(fs, args)

	s, err := sim.New(*cfg)
	if err != nil {
		fatal(err)
	}
	s.Start()
	fmt.Printf("集群已启动: %d 个工作负载, %d 个节点, %d 个容器\n",
		cfg.WorkloadCount, cfg.NodeCount, len(s.Build().Containers))
	fmt.Printf("旧证书将在 %s 后到期;文件根目录: %s\n", cfg.OldCertTTL, cfg.DataDir)
	fmt.Printf("仪表盘: http://localhost%s\n", *addr)
	fmt.Println("操作:页面上点击「执行轮换」→ 观察曲线 → 按批次重启 → 生成比对报告")
	if err := httpListen(*addr, web.New(s).Mux()); err != nil {
		fatal(err)
	}
}

func runDemo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	cfg, dataDir, _ := commonFlagsWith(fs, args)

	s, err := sim.New(*cfg)
	if err != nil {
		fatal(err)
	}
	s.Start()
	total := len(s.Build().Containers)
	fmt.Printf("== 阶段0 集群就绪: %d 工作负载 / %d 节点 / %d 容器 ==\n",
		cfg.WorkloadCount, cfg.NodeCount, total)
	sc := s.Scan()
	fmt.Printf("静态扫描: 可自动换证 %d, 永不更新 %d, 自动换证最大延迟上界 %.1fs\n",
		sc.WillAutoUpdate, sc.NeverUpdates, sc.BoundsP50P95MaxSec[2])
	for layer, n := range sc.ByLayer {
		fmt.Printf("  故障层 [%s]: %d 个\n", layer, n)
	}

	// ---- 阶段1: 轮换 -------------------------------------------------------
	time.Sleep(3 * time.Second)
	if err := s.Rotate(); err != nil {
		fatal(err)
	}
	fmt.Println("\n== 阶段1 Secret 已轮换(v2 写入 apiserver 模拟存储),等待节点同步与应用重读 ==")

	// Wait until every predicted auto-updater has switched, or the bound window
	// plus margin elapses — this is also the "missed prediction" detector.
	maxWait := time.Duration(sc.BoundsP50P95MaxSec[2]*1.5+15) * time.Second
	deadline := time.Now().Add(maxWait)
	autoTargets := sc.WillAutoUpdate
	for time.Now().Before(deadline) {
		v2 := countLoaded(s, "v2")
		if v2 >= autoTargets {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(2 * time.Second) // let stragglers prove they really won't update

	// ---- 阶段2: 预判 vs 实测(重启前) --------------------------------------
	rep1 := s.BuildReport()
	fmt.Println("\n== 阶段2 预判 vs 实测(重启前) ==")
	printReport(rep1)
	if rep1.Missed != 0 {
		fmt.Printf("!! 发现 %d 个漏判:扫描认为能自动更新,实际没有\n", rep1.Missed)
	}

	// ---- 阶段3: 按计划批次重启永不更新的容器 -------------------------------
	fmt.Println("\n== 阶段3 按轮换计划批次重启 ==")
	pl := s.Plan()
	for i := range pl.Batches {
		ids, err := s.RestartBatch(i + 1)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("  批次 %d (tier=%d): 重启 %d 个: %v\n", i+1, pl.Batches[i].Tier, len(ids), shortIDs(ids))
		time.Sleep(800 * time.Millisecond)
	}

	// ---- 阶段4: 终态核验 ---------------------------------------------------
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if countLoaded(s, "v2") == total {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	rep2 := s.BuildReport()
	fmt.Println("\n== 阶段4 重启后终态 ==")
	printReport(rep2)

	reportPath := filepath.Join(*dataDir, "rotation-report.json")
	raw, _ := json.MarshalIndent(map[string]any{
		"beforeRestart": rep1, "afterRestart": rep2,
		"plan": pl, "scan": sc,
	}, "", "  ")
	if err := os.WriteFile(reportPath, raw, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("\n完整 JSON 报告: %s\n", reportPath)

	s.Stop()
	if rep1.Missed != 0 || rep2.Missed != 0 || rep1.FalseAlarm != 0 || rep2.FalseAlarm != 0 ||
		countLoaded(s, "v2") != total {
		os.Exit(1)
	}
	fmt.Println("结论: 预判与实测完全一致,无漏网的永不更新容器;全部容器最终加载 v2。")
}

func countLoaded(s *sim.Sim, version string) int {
	n := 0
	for _, c := range s.Build().Containers {
		c.Mu.RLock()
		if c.LoadedVersion == version {
			n++
		}
		c.Mu.RUnlock()
	}
	return n
}

func shortIDs(ids []string) []string {
	if len(ids) <= 6 {
		return ids
	}
	return append(append([]string{}, ids[:6]...), fmt.Sprintf("...+%d", len(ids)-6))
}

func printReport(r *sim.Report) {
	fmt.Printf("容器 %d | 一致 %d | 漏判 %d | 误判 %d | 超延迟上界 %d | 计划重启治愈 %d\n",
		r.Total, r.Consistent, r.Missed, r.FalseAlarm, r.OverBound, r.RestartHealed)
	fmt.Printf("预判永不更新 %d, 实测仍持旧证 %d\n", r.PredictedNeverCnt, r.ActualNeverCnt)
	for _, row := range r.Rows {
		if row.Verdict == "consistent" || row.Verdict == "restarted" {
			continue
		}
		el := "—"
		if row.SwitchElapsed != nil {
			el = fmt.Sprintf("%.1fs", *row.SwitchElapsed)
		}
		fmt.Printf("  [%s] %s %s/%s 预判%v 实测%v 耗时%s\n",
			row.Verdict, row.ContainerID, row.Mount, row.Read,
			row.PredictedUpdate, row.ActualUpdated, el)
	}
}

func commonFlagsWith(fs *flag.FlagSet, args []string) (*sim.Config, *string, *int64) {
	cfg := &sim.Config{
		SampleEvery: 500 * time.Millisecond,
		VerifyEvery: time.Second,
		NewCertTTL:  365 * 24 * time.Hour,
	}
	workloads := fs.Int("workloads", 320, "工作负载数量")
	nodes := fs.Int("nodes", 8, "节点数量")
	oldTTL := fs.Duration("old-ttl", 3*time.Minute, "旧证书有效期(模拟压缩时间,真实场景对应 3 天)")
	data := fs.String("data", filepath.Join(os.TempDir(), "certrot-data"), "本地真实文件操作的根目录")
	seed := fs.Int64("seed", 42, "随机种子")
	_ = fs.Parse(args)
	cfg.WorkloadCount = *workloads
	cfg.NodeCount = *nodes
	cfg.OldCertTTL = *oldTTL
	cfg.DataDir = *data
	cfg.Seed = *seed
	return cfg, data, seed
}

func httpListen(addr string, mux *http.ServeMux) error {
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
