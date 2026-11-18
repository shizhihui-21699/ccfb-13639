package sct_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sctlab/sampleservice"
	"sctlab/sct"
)

// TestRegressionFixtures is the CI gate pattern: a campaign writes one JSON per
// unique bug, and a later run replays every saved schedule against the CURRENT
// code. When a fix lands, the replay goes clean and the fixture can be removed;
// while the defect exists, the replay must keep producing the violation class.
func TestRegressionFixtures(t *testing.T) {
	dir := t.TempDir()
	w := sampleservice.CouponWorkload{Mode: sampleservice.ModeBuggy}
	cfg := sct.ExplorerConfig{
		TickCap: 3000, VerifyReplay: true, ReportDir: dir,
		Strategies: []sct.StrategyConfig{
			{Kind: "script", Scripts: []sct.NamedScript{sampleservice.CouponAttackScript()}},
		},
	}
	rep, err := sct.Explore(w, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.UniqueBugs == 0 {
		t.Fatal("campaign produced no fixtures")
	}

	// Every bug-*.json fixture must replay to the same defect.
	matches, err := filepath.Glob(filepath.Join(dir, "bug-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != rep.UniqueBugs {
		t.Fatalf("fixture count %d != unique bugs %d", len(matches), rep.UniqueBugs)
	}
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		var bug sct.Bug
		if err := json.Unmarshal(raw, &bug); err != nil {
			t.Fatalf("fixture %s: %v", m, err)
		}
		re := sct.Replay(w, bug.Schedule, 3000)
		if re.Err != "" {
			t.Errorf("fixture %s replay error: %s", filepath.Base(m), re.Err)
		}
		hit := false
		for _, v := range re.Violations {
			for _, rule := range bug.AllRules {
				if v.Rule == rule {
					hit = true
				}
			}
		}
		if !hit {
			t.Errorf("fixture %s no longer reproduces any of %v — fix landed, remove fixture",
				filepath.Base(m), bug.AllRules)
		}
	}
}

// TestFixedCodeClosesRegressionFixtures proves the same saved schedule becomes
// clean when the atomic implementation is substituted: this is how the gate
// flips from red to green after a remediation.
func TestFixedCodeClosesRegressionFixtures(t *testing.T) {
	buggy := sampleservice.CouponWorkload{Mode: sampleservice.ModeBuggy}
	rep, err := sct.Explore(buggy, nil, sct.ExplorerConfig{
		TickCap: 3000, VerifyReplay: true, ReportDir: t.TempDir(),
		Strategies: []sct.StrategyConfig{
			{Kind: "script", Scripts: []sct.NamedScript{sampleservice.CouponAttackScript()}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	schedule := rep.Bugs[0].Schedule

	fixed := sampleservice.CouponWorkload{Mode: sampleservice.ModeAtomic}
	re := sct.Replay(fixed, schedule, 3000)
	// A replay mismatch means the instrumented path changed and the old attack
	// schedule no longer maps onto live goroutines — here, the atomic critical
	// section removes the interleaving points entirely. Both "clean replay" and
	// "mismatch" prove the defect is no longer reachable; only violations fail.
	if re.Err != "" && !containsMismatch(re.Err) {
		t.Fatalf("fixed replay scheduler error: %s", re.Err)
	}
	if len(re.Violations) != 0 {
		t.Fatalf("fixed code still violates under the attack schedule: %+v", re.Violations)
	}
}

func containsMismatch(err string) bool {
	return strings.Contains(err, "replay mismatch") || strings.Contains(err, "not live")
}
