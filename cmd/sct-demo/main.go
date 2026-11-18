// Command sct-demo runs the full concurrency-defect exploration campaign
// against the sample service: every workload (coupon, permission, account) in
// both buggy and fixed modes, under every exploration strategy, and prints a
// coverage + kill-matrix table plus JSON reports under reports/.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sctlab/sampleservice"
	"sctlab/sct"
)

func main() {
	root := reportRoot()
	seeds := []uint64{1, 2, 3, 7, 11, 17, 23, 31, 42, 59, 71, 89}

	type spec struct {
		name     string
		workload func(mode sampleservice.Mode) sct.Workload
		script   sct.NamedScript
	}
	specs := []spec{
		{"coupon", func(m sampleservice.Mode) sct.Workload { return sampleservice.CouponWorkload{Mode: m} }, sampleservice.CouponAttackScript()},
		{"permission", func(m sampleservice.Mode) sct.Workload { return sampleservice.PermissionWorkload{Mode: m} }, sampleservice.PermissionAttackScript()},
		{"account", func(m sampleservice.Mode) sct.Workload { return sampleservice.AccountWorkload{Mode: m} }, sampleservice.AccountAttackScript()},
	}

	var failed bool
	for _, sp := range specs {
		for _, mode := range []sampleservice.Mode{sampleservice.ModeBuggy, sampleservice.ModeAtomic} {
			w := sp.workload(mode)
			cfg := sct.ExplorerConfig{
				TickCap:      5000,
				VerifyReplay: true,
				ReportDir:    filepath.Join(root, sp.name+"-"+mode.String()),
				Strategies: []sct.StrategyConfig{
					{Kind: "random", Seeds: seeds},
					{Kind: "pct", PCTDepth: 2, Seeds: seeds[:6]},
					{Kind: "pct", PCTDepth: 4, Seeds: seeds[:6]},
					{Kind: "dfs", DFSDepth: 6, DFSRuns: 128},
					{Kind: "script", Scripts: []sct.NamedScript{sp.script}},
				},
			}
			report, err := sct.Explore(w, sampleservice.KnownPoints(), cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "exploration failed for %s/%s: %v\n", sp.name, mode, err)
				failed = true
				continue
			}
			printReport(sp.name, mode, report)

			// The campaign's exit code encodes the two guarantees the tool is
			// built on: buggy code MUST be caught, fixed code MUST stay clean.
			if mode == sampleservice.ModeBuggy && report.UniqueBugs == 0 {
				fmt.Printf("  !! FAIL: no defect found in buggy %s workload\n", sp.name)
				failed = true
			}
			if mode == sampleservice.ModeAtomic && report.UniqueBugs != 0 {
				fmt.Printf("  !! FAIL: false positive on fixed %s workload\n", sp.name)
				failed = true
			}
		}
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("\nall campaigns behaved as expected: buggy variants caught, atomic variants clean")
}

func reportRoot() string {
	dir := filepath.Join("..", "reports")
	if wd, err := os.Getwd(); err == nil && filepath.Base(wd) != "cmd" {
		dir = filepath.Join("reports")
	}
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

func printReport(name string, mode sampleservice.Mode, r *sct.Report) {
	line := strings.Repeat("-", 78)
	fmt.Printf("\n%s\n%s / %s — %d runs, %d unique bugs\n%s\n",
		line, name, mode, r.Runs, r.UniqueBugs, line)

	c := r.Coverage
	pointPct := 0
	if c.PointsTotal > 0 {
		pointPct = 100 * len(c.PointsReached) / c.PointsTotal
	}
	fmt.Printf("coverage: points %d/%d (%d%%), point-edges %d, goroutine switches %d/%d, windows %d (interfered %d), distinct schedules %d/%d\n",
		len(c.PointsReached), c.PointsTotal, pointPct,
		c.EdgesSeen, c.SchedEdgesSeen, c.SchedEdgesTotal,
		c.WindowsOpened, c.WindowsInterfered, c.DistinctSchedules, c.TotalRuns)

	fmt.Printf("%-24s %8s %8s\n", "strategy", "runs", "kill runs")
	for strat, total := range r.StrategyRuns {
		fmt.Printf("%-24s %8d %8d\n", strat, total, r.KillMatrix[strat])
	}
	for i, bug := range r.Bugs {
		replay := "unverified"
		if bug.ReplayOK {
			replay = "replay OK"
		}
		fmt.Printf("bug[%d] %s (%s) %s\n", i, bug.Violation.Rule, replay, bug.Violation.Message)
		fmt.Printf("       schedule(%d)=%v\n", len(bug.Schedule), compact(bug.Schedule))
	}
}

func compact(xs []int) string {
	var b strings.Builder
	for i, x := range xs {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%d", x)
	}
	return b.String()
}
