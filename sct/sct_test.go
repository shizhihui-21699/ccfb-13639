package sct_test

import (
	"context"
	"testing"

	"sctlab/sampleservice"
	"sctlab/sct"
)

// campaignCfg is the standard campaign used by the tests: small but covering
// every strategy.
func campaignCfg(dir string) sct.ExplorerConfig {
	return sct.ExplorerConfig{
		TickCap:      3000,
		VerifyReplay: true,
		ReportDir:    dir,
		Strategies: []sct.StrategyConfig{
			{Kind: "random", Seeds: []uint64{1, 2, 3, 4, 5, 6, 7, 8}},
			{Kind: "pct", PCTDepth: 2, Seeds: []uint64{1, 2, 3, 4}},
			{Kind: "pct", PCTDepth: 4, Seeds: []uint64{1, 2, 3, 4}},
			{Kind: "dfs", DFSDepth: 6, DFSRuns: 64},
			{Kind: "script", Scripts: []sct.NamedScript{}},
		},
	}
}

func withScript(cfg sct.ExplorerConfig, ns sct.NamedScript) sct.ExplorerConfig {
	for i := range cfg.Strategies {
		if cfg.Strategies[i].Kind == "script" {
			cfg.Strategies[i].Scripts = []sct.NamedScript{ns}
		}
	}
	return cfg
}

func TestBuggyWorkloadsAreCaught(t *testing.T) {
	cases := []struct {
		name     string
		w        sct.Workload
		script   sct.NamedScript
		wantRule string
	}{
		{"coupon", sampleservice.CouponWorkload{Mode: sampleservice.ModeBuggy},
			sampleservice.CouponAttackScript(), "coupon-single-redemption"},
		{"permission", sampleservice.PermissionWorkload{Mode: sampleservice.ModeBuggy},
			sampleservice.PermissionAttackScript(), "authz-use-after-revoke-ordering"},
		{"account", sampleservice.AccountWorkload{Mode: sampleservice.ModeBuggy},
			sampleservice.AccountAttackScript(), "acct-no-serial-equivalent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := withScript(campaignCfg(t.TempDir()), tc.script)
			rep, err := sct.Explore(tc.w, nil, cfg)
			if err != nil {
				t.Fatalf("explore: %v", err)
			}
			if rep.UniqueBugs == 0 {
				t.Fatalf("expected defects in buggy %s, got none", tc.name)
			}
			found := false
			for _, b := range rep.Bugs {
				if b.Violation.Rule == tc.wantRule {
					found = true
					if !b.ReplayOK {
						t.Errorf("bug %s not replay-stable", tc.wantRule)
					}
					if len(b.Schedule) == 0 {
						t.Errorf("bug %s has empty replay schedule", tc.wantRule)
					}
				}
			}
			if !found {
				t.Errorf("expected rule %s among %d bugs", tc.wantRule, rep.UniqueBugs)
			}
		})
	}
}

func TestAtomicWorkloadsStayClean(t *testing.T) {
	cases := []struct {
		name   string
		w      sct.Workload
		script sct.NamedScript
	}{
		{"coupon", sampleservice.CouponWorkload{Mode: sampleservice.ModeAtomic}, sampleservice.CouponAttackScript()},
		{"permission", sampleservice.PermissionWorkload{Mode: sampleservice.ModeAtomic}, sampleservice.PermissionAttackScript()},
		{"account", sampleservice.AccountWorkload{Mode: sampleservice.ModeAtomic}, sampleservice.AccountAttackScript()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := withScript(campaignCfg(t.TempDir()), tc.script)
			rep, err := sct.Explore(tc.w, nil, cfg)
			if err != nil {
				t.Fatalf("explore: %v", err)
			}
			if rep.UniqueBugs != 0 {
				for _, b := range rep.Bugs {
					t.Errorf("false positive: %s — %s", b.Violation.Rule, b.Violation.Message)
				}
			}
		})
	}
}

func TestReplayIsBitPerfect(t *testing.T) {
	w := sampleservice.CouponWorkload{Mode: sampleservice.ModeBuggy}
	rep, err := sct.Explore(w, nil, campaignCfg(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if rep.UniqueBugs == 0 {
		t.Fatal("setup: no bugs found")
	}
	for _, bug := range rep.Bugs {
		re := sct.Replay(w, bug.Schedule, 3000)
		if re.Err != "" {
			t.Errorf("replay of %s ended with scheduler error: %s", bug.Fingerprint, re.Err)
		}
		// Trace shape must be identical: same event kinds and points in order.
		if len(re.Trace) != len(bug.Trace) {
			t.Fatalf("replay trace length %d != original %d", len(re.Trace), len(bug.Trace))
		}
		for i := range re.Trace {
			if re.Trace[i].GID != bug.Trace[i].GID ||
				re.Trace[i].Kind != bug.Trace[i].Kind ||
				re.Trace[i].Point != bug.Trace[i].Point {
				t.Fatalf("replay diverged at event %d: replay=%+v orig=%+v",
					i, re.Trace[i], bug.Trace[i])
			}
		}
	}
}

func TestAttackScriptsTriggerDefect(t *testing.T) {
	cases := []struct {
		name   string
		w      sct.Workload
		script sct.NamedScript
	}{
		{"coupon", sampleservice.CouponWorkload{Mode: sampleservice.ModeBuggy}, sampleservice.CouponAttackScript()},
		{"permission", sampleservice.PermissionWorkload{Mode: sampleservice.ModeBuggy}, sampleservice.PermissionAttackScript()},
		{"account", sampleservice.AccountWorkload{Mode: sampleservice.ModeBuggy}, sampleservice.AccountAttackScript()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sct.ExplorerConfig{
				TickCap: 3000, VerifyReplay: true, ReportDir: t.TempDir(),
				Strategies: []sct.StrategyConfig{{Kind: "script", Scripts: []sct.NamedScript{tc.script}}},
			}
			rep, err := sct.Explore(tc.w, nil, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if rep.UniqueBugs == 0 {
				t.Fatalf("attack script %s produced no violation", tc.script.Label)
			}
			anyStable := false
			for _, b := range rep.Bugs {
				if b.ReplayOK {
					anyStable = true
				}
			}
			if !anyStable {
				t.Fatal("no script-triggered bug is replay-stable")
			}
		})
	}
}

func TestScriptRunViaExplore(t *testing.T) {
	w := sampleservice.PermissionWorkload{Mode: sampleservice.ModeBuggy}
	cfg := sct.ExplorerConfig{
		TickCap: 3000, VerifyReplay: true, ReportDir: t.TempDir(),
		Strategies: []sct.StrategyConfig{
			{Kind: "script", Scripts: []sct.NamedScript{sampleservice.PermissionAttackScript()}},
		},
	}
	rep, err := sct.Explore(w, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.UniqueBugs == 0 {
		t.Fatal("permission attack script failed to trigger the TOCTOU")
	}
}

func TestCoverageMetrics(t *testing.T) {
	w := sampleservice.CouponWorkload{Mode: sampleservice.ModeBuggy}
	rep, err := sct.Explore(w, nil, campaignCfg(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Coverage
	if c.PointsTotal != 5 {
		t.Errorf("workload-scoped point denominator = %d, want 5", c.PointsTotal)
	}
	if len(c.PointsReached) == 0 {
		t.Error("no points reached")
	}
	if c.SchedEdgesTotal != 2 || c.SchedEdgesSeen != 2 {
		t.Errorf("goroutine switch coverage = %d/%d, want 2/2", c.SchedEdgesSeen, c.SchedEdgesTotal)
	}
	if c.WindowsInterfered == 0 {
		t.Error("buggy campaign should observe interfered check/use windows")
	}
	if c.DistinctSchedules <= 1 {
		t.Error("campaign explored only one distinct schedule")
	}
}

// TestNoDataRaceInBuggyVariant guards the central claim: the planted defects
// are atomicity violations with no underlying data race. Run with -race.
func TestNoDataRaceInBuggyVariant(t *testing.T) {
	w := sampleservice.CouponWorkload{Mode: sampleservice.ModeBuggy}
	cfg := sct.ExplorerConfig{
		TickCap: 2000, ReportDir: t.TempDir(),
		Strategies: []sct.StrategyConfig{{Kind: "random", Seeds: []uint64{1, 2, 3}}},
	}
	if _, err := sct.Explore(w, nil, cfg); err != nil {
		t.Fatal(err)
	}
}

// TestInstrumentationIsNoopOutsideSCT ensures the same instrumented handlers
// run unmodified when no controller is attached (production path).
func TestInstrumentationIsNoopOutsideSCT(t *testing.T) {
	svc := sampleservice.NewService(sampleservice.ModeBuggy)
	ctx := context.Background()
	if err := svc.Coupons.Redeem(ctx, 0, "C1"); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if err := svc.Coupons.Redeem(ctx, 1, "C1"); err != sampleservice.ErrAlreadyRedeemed {
		t.Fatalf("second redeem: got %v want ErrAlreadyRedeemed", err)
	}
}
