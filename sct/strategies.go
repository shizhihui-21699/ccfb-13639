package sct

import (
	"errors"
	"fmt"
)

// errEnded tells the controller the decider has no more moves. For script and
// replay deciders this is a normal, expected termination.
var errEnded = errors.New("sct: schedule exhausted")

// pcg is a tiny deterministic PCG-XSH-RR generator so schedules depend only on
// the seed, never on Go runtime map iteration or wall clock.
type pcg struct{ state uint64 }

func newPCG(seed uint64) *pcg { return &pcg{state: seed + 0x9E3779B97F4A7C15} }

func (p *pcg) uint32() uint32 {
	old := p.state
	p.state = old*6364136223846793005 + 1442695040888963407
	xorshifted := uint32(((old >> 18) ^ old) >> 27)
	rot := uint(old >> 59)
	return (xorshifted >> rot) | (xorshifted << ((-rot) & 31))
}

func (p *pcg) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(p.uint32()) % n
}

// ---- RandomDecider: probabilistic concurrency testing ----------------------
//
// At every decision point pick uniformly at random among live goroutines.
// Cheap and surprisingly effective; used as the baseline and for fuzzing.
type RandomDecider struct {
	rng *pcg
}

func NewRandomDecider(seed uint64) *RandomDecider {
	return &RandomDecider{rng: newPCG(seed)}
}

func (d *RandomDecider) Decide(e TraceEntry, live []int) (int, error) {
	return live[d.rng.intn(len(live))], nil
}

// ---- ReplayDecider: deterministic replay ------------------------------------
//
// Replays a previously recorded gid schedule. A schedule is just the sequence
// of decisions (the gid chosen at each handoff); the trace's event structure is
// expected to match because the workload is deterministic. A mismatch means
// the code under test changed and the regression needs re-triaging.
type ReplayDecider struct {
	schedule []int
	idx      int
}

func NewReplayDecider(schedule []int) *ReplayDecider {
	return &ReplayDecider{schedule: append([]int(nil), schedule...)}
}

func (d *ReplayDecider) Decide(e TraceEntry, live []int) (int, error) {
	if d.idx >= len(d.schedule) {
		return -1, errEnded
	}
	gid := d.schedule[d.idx]
	d.idx++
	if !contains(live, gid) {
		return -1, fmt.Errorf("sct: replay mismatch at decision %d: gid %d not live %v (instrumented code changed?)", d.idx-1, gid, live)
	}
	return gid, nil
}

// ---- ScriptDecider: hand-written attack / regression script -----------------
//
// A ScriptStep forces a specific goroutine to run, optionally until it reaches
// an expected point. Point expectations are advisory: mismatch is reported on
// the event that failed, which keeps regression scripts legible. Use this to
// encode known attack patterns (two redeemers interleaved at check/use) and to
// keep bug fixes locked down in CI.
type ScriptStep struct {
	GID       int    `json:"gid"`
	WantPoint string `json:"want_point,omitempty"` // expected point reached at this step, "" = don't care
}

type ScriptDecider struct {
	steps    []ScriptStep
	idx      int
	fallback Decider
}

// NewScriptDecider builds a decider that forces the gid sequence in steps for
// the critical prefix of an attack, then delegates all remaining decisions to
// fallback so the run drains to completion deterministically. Pass nil to use
// the deterministic lowest-live-gid fallback. Attack scripts therefore only
// need to pin the interleaving that matters, not every tail decision.
func NewScriptDecider(steps []ScriptStep, fallback ...Decider) *ScriptDecider {
	d := &ScriptDecider{steps: append([]ScriptStep(nil), steps...)}
	if len(fallback) > 0 && fallback[0] != nil {
		d.fallback = fallback[0]
	} else {
		d.fallback = &lowestGIDDecider{}
	}
	return d
}

// lowestGIDDecider always resumes the runnable goroutine with the smallest id.
type lowestGIDDecider struct{}

func (lowestGIDDecider) Decide(e TraceEntry, live []int) (int, error) {
	return live[0], nil
}

func (d *ScriptDecider) Decide(e TraceEntry, live []int) (int, error) {
	if d.idx >= len(d.steps) {
		return d.fallback.Decide(e, live)
	}
	s := d.steps[d.idx]
	d.idx++
	if s.WantPoint != "" && e.Point != "" && e.Point != s.WantPoint {
		return -1, fmt.Errorf("sct: script step %d expected point %q but reached %q", d.idx-1, s.WantPoint, e.Point)
	}
	if !contains(live, s.GID) {
		return -1, fmt.Errorf("sct: script step %d selected dead gid %d (live %v)", d.idx-1, s.GID, live)
	}
	return s.GID, nil
}

// ---- PCTDecider: randomized priority scheduling (Burckhardt et al.) ---------
//
// Every goroutine gets a random distinct initial priority and runs whenever it
// is the highest-priority live goroutine. At d-1 random decision positions the
// currently executing goroutine is demoted below every live peer, forcing a
// preemption there. PCT has a probabilistic guarantee: any bug requiring d
// specific preemptions is hit with probability at least 1 / (n * k^(d-1)) per
// run (n goroutines, k max events), which is why a handful of seeds usually
// surfaces 2-preemption bugs like our TOCTOU cases.
type PCTDecider struct {
	rng      *pcg
	prio     map[int]int
	changeAt map[int]bool // decision index -> demotion event
	depth    int
	tick     int
}

func NewPCTDecider(n, depth int, estimatedEvents int, seed uint64) *PCTDecider {
	rng := newPCG(seed)
	prio := make(map[int]int, n)
	perm := rng.perm(n)
	for i, gid := range perm {
		prio[gid] = n - i // distinct priorities, highest first
	}
	changeAt := make(map[int]bool, depth-1)
	if depth > 1 && estimatedEvents > 1 {
		for len(changeAt) < depth-1 {
			changeAt[1+rng.intn(estimatedEvents-1)] = true
		}
	}
	return &PCTDecider{rng: rng, prio: prio, changeAt: changeAt, depth: depth}
}

func (d *PCTDecider) Decide(e TraceEntry, live []int) (int, error) {
	d.tick++
	if d.changeAt[d.tick] {
		// Demote the goroutine that just yielded below every live peer, so a
		// different goroutine is picked at this decision — a forced preemption.
		lowest := d.prio[live[0]]
		for _, g := range live[1:] {
			if d.prio[g] < lowest {
				lowest = d.prio[g]
			}
		}
		d.prio[e.GID] = lowest - 1
	}
	best, bestP := live[0], d.prio[live[0]]
	for _, g := range live[1:] {
		if p := d.prio[g]; p > bestP || (p == bestP && g < best) {
			best, bestP = g, p
		}
	}
	return best, nil
}

// ---- DFSDecider: bounded exhaustive enumeration across runs -----------------
//
// Pure Go cannot snapshot/rollback goroutine state mid-run, so exhaustive
// exploration is done ACROSS runs: each run consumes one fixed gid sequence
// (an odometer word over [0,n)), and Run is invoked once per word. With depth
// D this covers every interleaving whose first D decisions matter for small
// goroutine counts; traces are deduplicated by the explorer afterward.
type DFSDecider struct {
	n        int
	seq      []int
	idx      int
	maxRuns  int
	run      int
	fallback Decider
}

// NewDFSDecider creates an enumerator for n goroutines. depth bounds the number
// of decisions pinned per run; later decisions use a deterministic lowest-gid
// fallback so every run still drains to completion. maxRuns bounds total work
// (n^depth explodes quickly).
func NewDFSDecider(n, depth, maxRuns int) *DFSDecider {
	return &DFSDecider{n: n, seq: make([]int, depth), maxRuns: maxRuns, fallback: &lowestGIDDecider{}}
}

// Next advances the odometer. Returns false when all words are consumed.
func (d *DFSDecider) Next() bool {
	if d.run >= d.maxRuns {
		return false
	}
	if d.run > 0 {
		carry := 1
		for i := len(d.seq) - 1; i >= 0 && carry > 0; i-- {
			d.seq[i] += carry
			if d.seq[i] == d.n {
				d.seq[i] = 0
				carry = 1
			} else {
				carry = 0
			}
		}
		if carry > 0 {
			return false // all words enumerated
		}
	}
	d.run++
	d.idx = 0
	return true
}

func (d *DFSDecider) Decide(e TraceEntry, live []int) (int, error) {
	if d.idx >= len(d.seq) {
		return d.fallback.Decide(e, live)
	}
	want := d.seq[d.idx]
	d.idx++
	if !contains(live, want) {
		// The word targeted a goroutine that has already exited. Falling back
		// to the lowest live gid keeps the run draining to completion instead
		// truncating it (truncation previously made most enumerated words
		// explore almost no interleaving); distinct tails still differentiate
		// runs through their earlier, valid decisions.
		return live[0], nil
	}
	return want, nil
}

// Sequence returns the current odometer word, for labelling runs in reports.
func (d *DFSDecider) Sequence() []int { return append([]int(nil), d.seq...) }

// perm returns a deterministic Fisher-Yates permutation of [0,n).
func (p *pcg) perm(n int) []int {
	xs := make([]int, n)
	for i := range xs {
		xs[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := p.intn(i + 1)
		xs[i], xs[j] = xs[j], xs[i]
	}
	return xs
}
