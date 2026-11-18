package sct

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Workload is one concurrent scenario against the code under test: a fresh
// state, N worker goroutines (each a request), and an oracle that judges the
// final state. Implementations build fresh state on every call — runs must be
// independent so schedules are replayable.
type Workload interface {
	Name() string
	// N is the number of concurrent request goroutines.
	N() int
	// Setup builds the per-run initial state (coupon table, ACL, balances...).
	Setup() State
	// Worker runs request number gid. It receives a state from Setup and an
	// sct-aware context; pass the context into store/handler calls.
	Worker(ctx context.Context, gid int, st State) error
	// Oracle judges the final state. It receives the full event trace so
	// ordering-based properties ("revoke happened before the privileged use")
	// can be decided, not just final-state properties. It must be pure given
	// (state, trace, windows).
	Oracle(st State, trace []TraceEntry, windows []TOCTOUWindow) []Violation
}

// PointLister is an optional workload capability listing the instrumentation
// points that belong to this workload. It scopes point coverage to the
// workload's own denominator instead of a global point catalogue.
type PointLister interface {
	Points() []string
}

// State is a marker for per-run workload state.
type State interface{}

// Violation is one concrete defect finding.
type Violation struct {
	Rule     string `json:"rule"`     // invariant id, e.g. "coupon-single-redemption"
	Message  string `json:"message"`  // human-readable explanation
	Resource string `json:"resource"` // affected resource id
	GIDs     []int  `json:"gids"`     // goroutines involved
	Kind     string `json:"kind"`     // "invariant" | "toctou" | "serializability"
}

// RunResult is everything observed in one run.
type RunResult struct {
	Index       int            `json:"index"`
	Strategy    string         `json:"strategy"`
	Seed        uint64         `json:"seed,omitempty"`
	ScriptLabel string         `json:"script_label,omitempty"`
	DFSWord     []int          `json:"dfs_word,omitempty"`
	Schedule    []int          `json:"schedule"`
	Trace       []TraceEntry   `json:"trace"`
	Windows     []TOCTOUWindow `json:"windows"`
	Violations  []Violation    `json:"violations"`
	WorkerErrs  []string       `json:"worker_errors,omitempty"`
	PointHits   map[string]int `json:"point_hits"`
	Edges       []Edge         `json:"edges"`
	SchedEdges  [][2]int       `json:"sched_edges"`
	ReplayOK    bool           `json:"replay_ok"`
	Err         string         `json:"err,omitempty"`
	Fingerprint string         `json:"fingerprint"`
}

// StrategyConfig describes one exploration strategy to run.
type StrategyConfig struct {
	Kind     string        `json:"kind"` // random | pct | dfs | script
	Seeds    []uint64      `json:"seeds,omitempty"`
	PCTDepth int           `json:"pct_depth,omitempty"`
	DFSDepth int           `json:"dfs_depth,omitempty"`
	DFSRuns  int           `json:"dfs_runs,omitempty"`
	Scripts  []NamedScript `json:"scripts,omitempty"`
}

// NamedScript bundles a hand-written attack script with a label.
type NamedScript struct {
	Label string       `json:"label"`
	Steps []ScriptStep `json:"steps"`
}

// ExplorerConfig controls a full exploration campaign.
type ExplorerConfig struct {
	TickCap      int              `json:"tick_cap"`
	Strategies   []StrategyConfig `json:"strategies"`
	VerifyReplay bool             `json:"verify_replay"`
	ReportDir    string           `json:"report_dir,omitempty"`
}

// Report is the campaign-level output.
type Report struct {
	Workload     string         `json:"workload"`
	Runs         int            `json:"runs"`
	UniqueBugs   int            `json:"unique_bugs"`
	Violations   []Violation    `json:"violations"`
	Bugs         []Bug          `json:"bugs"`
	Coverage     Coverage       `json:"coverage"`
	RunResults   []RunResult    `json:"run_results"`
	KillMatrix   map[string]int `json:"kill_matrix"` // strategy -> runs that produced >=1 violation
	StrategyRuns map[string]int `json:"strategy_runs"`
}

// Bug is a deduplicated violation with the shortest reproducing schedule.
type Bug struct {
	Fingerprint string    `json:"fingerprint"`
	Violation   Violation `json:"violation"`
	// AllRules is the full set of violation rules from the run that produced
	// this bug; replay verification compares against the replay's rule set.
	AllRules []string     `json:"all_rules"`
	Schedule []int        `json:"schedule"`
	Trace    []TraceEntry `json:"trace"`
	ReplayOK bool         `json:"replay_ok"`
}

// Coverage quantifies how much of the interleaving space was explored.
type Coverage struct {
	// PointCoverage: union of instrumented points reached / points declared.
	PointsReached map[string]int `json:"points_reached"`
	PointsTotal   int            `json:"points_total"`
	// EdgeCoverage: distinct point-to-point transitions observed.
	EdgesSeen int `json:"edges_seen"`
	// SchedEdgeCoverage: distinct goroutine-switch transitions (gA->gB) seen
	// across the campaign. With n request goroutines the possible universe is
	// n*(n-1) ordered pairs; this is the metric that actually measures how
	// much of the interleaving space was exercised.
	SchedEdgesSeen  int `json:"sched_edges_seen"`
	SchedEdgesTotal int `json:"sched_edges_total"`
	// WindowCoverage: check/use windows opened, and how many were observed
	// under interference (the dangerous configuration).
	WindowsOpened     int `json:"windows_opened"`
	WindowsInterfered int `json:"windows_interfered"`
	// DistinctSchedules: number of unique (trace shape, schedule) combinations.
	DistinctSchedules int `json:"distinct_schedules"`
	// TotalRuns / capped runs, for interpreting exhaustive strategy coverage.
	TotalRuns int `json:"total_runs"`
}

// Explore runs the full campaign for one workload and returns the report.
func Explore(w Workload, knownPoints []string, cfg ExplorerConfig) (*Report, error) {
	if cfg.TickCap <= 0 {
		cfg.TickCap = 10000
	}
	// Prefer the workload's own point set so the coverage denominator reflects
	// only points this workload can reach.
	if pl, ok := w.(PointLister); ok {
		knownPoints = pl.Points()
	}
	report := &Report{
		Workload:     w.Name(),
		KillMatrix:   map[string]int{},
		StrategyRuns: map[string]int{},
		Coverage: Coverage{
			PointsReached: map[string]int{},
			PointsTotal:   len(knownPoints),
		},
	}
	seenTraces := map[string]bool{}
	bugIndex := map[string]*Bug{}
	edgeUnion := map[Edge]struct{}{}
	schedEdgeUnion := map[[2]int]struct{}{}

	runOne := func(idx int, decider Decider, label string, seed uint64, word []int) RunResult {
		res := runWorkload(w, decider, cfg.TickCap)
		res.Index = idx
		res.Strategy = label
		res.Seed = seed
		res.DFSWord = word
		res.Fingerprint = traceFingerprint(res.Trace)
		seenTraces[res.Fingerprint] = true

		for k, v := range res.PointHits {
			report.Coverage.PointsReached[k] += v
		}
		for _, e := range res.Edges {
			edgeUnion[e] = struct{}{}
		}
		for _, se := range res.SchedEdges {
			schedEdgeUnion[se] = struct{}{}
		}
		report.Coverage.WindowsOpened += len(res.Windows)
		for _, win := range res.Windows {
			if win.Interfered {
				report.Coverage.WindowsInterfered++
			}
		}
		if len(res.Violations) > 0 {
			report.KillMatrix[label]++
		}
		report.StrategyRuns[label]++

		// Replay verification: a bug is only trustworthy if its exact schedule
		// reproduces the same violation classes on a clean run that reaches
		// completion without scheduler errors.
		rules := violationRules(res.Violations)
		if len(res.Violations) > 0 && cfg.VerifyReplay {
			rep := runWorkload(w, NewReplayDecider(res.Schedule), cfg.TickCap)
			res.ReplayOK = rep.Err == "" && sameViolationRules(res.Violations, rep.Violations)
		}
		for _, v := range res.Violations {
			fp := bugFingerprint(v)
			candidate := &Bug{
				Fingerprint: fp, Violation: v, AllRules: rules,
				Schedule: append([]int(nil), res.Schedule...),
				Trace:    append([]TraceEntry(nil), res.Trace...),
				ReplayOK: res.ReplayOK,
			}
			existing, ok := bugIndex[fp]
			if !ok {
				bugIndex[fp] = candidate
				continue
			}
			// A verified bug always beats an unverified one; among equal
			// verification status keep the shortest reproducing schedule.
			if (candidate.ReplayOK && !existing.ReplayOK) ||
				(candidate.ReplayOK == existing.ReplayOK && len(candidate.Schedule) < len(existing.Schedule)) {
				bugIndex[fp] = candidate
			}
		}
		report.RunResults = append(report.RunResults, res)
		return res
	}

	idx := 0
	for _, sc := range cfg.Strategies {
		switch sc.Kind {
		case "random":
			for _, seed := range sc.Seeds {
				runOne(idx, NewRandomDecider(seed), "random", seed, nil)
				idx++
			}
		case "pct":
			depth := sc.PCTDepth
			if depth <= 0 {
				depth = 3
			}
			// Preemption points are chosen uniformly over the run's decision
			// positions. Estimate those from the point catalogue (each request
			// hits roughly points/n decisions), not from the tick cap, which
			// would spread the change points across thousands of unreachable
			// positions and make key-window preemptions nearly impossible.
			est := len(knownPoints) * w.N()
			if est < depth {
				est = depth + 1
			}
			for _, seed := range sc.Seeds {
				runOne(idx, NewPCTDecider(w.N(), depth, est, seed),
					fmt.Sprintf("pct-d%d", depth), seed, nil)
				idx++
			}
		case "dfs":
			depth, maxRuns := sc.DFSDepth, sc.DFSRuns
			if depth <= 0 {
				depth = 6
			}
			if maxRuns <= 0 {
				maxRuns = 256
			}
			dfs := NewDFSDecider(w.N(), depth, maxRuns)
			for dfs.Next() {
				word := dfs.Sequence()
				runOne(idx, dfs, "dfs", 0, word)
				idx++
			}
		case "script":
			for _, ns := range sc.Scripts {
				runOne(idx, NewScriptDecider(ns.Steps), "script:"+ns.Label, 0, nil)
				idx++
			}
		default:
			return nil, fmt.Errorf("sct: unknown strategy kind %q", sc.Kind)
		}
	}

	report.Runs = len(report.RunResults)
	report.Coverage.TotalRuns = report.Runs
	report.Coverage.DistinctSchedules = len(seenTraces)
	report.Coverage.EdgesSeen = len(edgeUnion)
	report.Coverage.SchedEdgesSeen = len(schedEdgeUnion)
	report.Coverage.SchedEdgesTotal = w.N() * (w.N() - 1)
	for _, b := range bugIndex {
		report.Bugs = append(report.Bugs, *b)
		report.Violations = append(report.Violations, b.Violation)
	}
	sort.Slice(report.Bugs, func(i, j int) bool { return report.Bugs[i].Fingerprint < report.Bugs[j].Fingerprint })
	report.UniqueBugs = len(report.Bugs)

	if cfg.ReportDir != "" {
		if err := writeReports(cfg.ReportDir, report); err != nil {
			return report, err
		}
	}
	return report, nil
}

// runWorkload executes a single instrumented run under the given decider.
func runWorkload(w Workload, decider Decider, tickCap int) RunResult {
	st := w.Setup()
	n := w.N()
	c := newController(decider, n, tickCap)
	res := RunResult{Schedule: nil, PointHits: map[string]int{}}

	var wg sync.WaitGroup
	errs := make([]string, n)
	for gid := 0; gid < n; gid++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			base := withController(context.Background(), c)
			ctx := WithGID(base, gid)
			defer func() {
				if r := recover(); r != nil {
					if r != errHalt {
						errs[gid] = fmt.Sprintf("g%d panic: %v", gid, r)
					}
				}
			}()
			c.enter(gid)
			if err := w.Worker(ctx, gid, st); err != nil {
				errs[gid] = err.Error()
			}
			c.exit(gid)
		}(gid)
	}
	wg.Wait()

	res.Schedule = c.Schedule()
	res.Trace = c.Trace()
	res.Windows = c.Windows()
	res.Edges = edgeKeys(c.Edges())
	res.SchedEdges = schedEdgeKeys(c.SchedEdges())
	for _, e := range res.Trace {
		if e.Kind == KindPoint || e.Kind == KindOpen || e.Kind == KindClose || e.Kind == KindMutate {
			res.PointHits[e.Point]++
		}
	}
	for _, m := range errs {
		if m != "" {
			res.WorkerErrs = append(res.WorkerErrs, m)
		}
	}
	if c.err != nil && c.err != errEnded {
		res.Err = c.err.Error()
	}
	res.Violations = w.Oracle(st, res.Trace, res.Windows)
	return res
}

// Replay reruns a workload with an exact saved schedule and returns the result;
// test code asserts the same violation (or none) reappears.
func Replay(w Workload, schedule []int, tickCap int) RunResult {
	if tickCap <= 0 {
		tickCap = 10000
	}
	return runWorkload(w, NewReplayDecider(schedule), tickCap)
}

func violationRules(vs []Violation) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vs {
		if !seen[v.Rule] {
			seen[v.Rule] = true
			out = append(out, v.Rule)
		}
	}
	sort.Strings(out)
	return out
}

// sameViolationRules compares violation *rule sets*: two runs are equivalent
// for replay purposes when they trigger the same classes of defect, even if
// the (unordered) structural violations differ in count or ordering.
func sameViolationRules(a, b []Violation) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	ra, rb := map[string]bool{}, map[string]bool{}
	for _, v := range a {
		ra[v.Rule] = true
	}
	for _, v := range b {
		rb[v.Rule] = true
	}
	if len(ra) != len(rb) {
		return false
	}
	for rule := range ra {
		if !rb[rule] {
			return false
		}
	}
	return true
}

func bugFingerprint(v Violation) string {
	gids := append([]int(nil), v.GIDs...)
	sort.Ints(gids)
	raw := v.Rule + "|" + v.Kind + "|" + v.Resource + "|" + intsToString(gids)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:10])
}

func traceFingerprint(trace []TraceEntry) string {
	var sb strings.Builder
	for _, e := range trace {
		fmt.Fprintf(&sb, "%d:%s:%s;", e.GID, e.Kind, e.Point)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:10])
}

func intsToString(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ",")
}

func schedEdgeKeys(m map[[2]int]struct{}) [][2]int {
	out := make([][2]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

func edgeKeys(m map[Edge]struct{}) []Edge {
	out := make([]Edge, 0, len(m))
	for e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

func writeReports(dir string, report *Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	full := filepath.Join(dir, "report.json")
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(full, b, 0o644); err != nil {
		return err
	}
	// One self-contained JSON per bug, checked in as CI regression fixtures.
	for _, bug := range report.Bugs {
		bp := filepath.Join(dir, "bug-"+bug.Fingerprint+".json")
		bb, err := json.MarshalIndent(bug, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(bp, bb, 0o644); err != nil {
			return err
		}
	}
	return nil
}
