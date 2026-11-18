// Package sct implements systematic concurrency testing for Go request handlers.
//
// The idea: instead of launching N goroutines and hoping the runtime scheduler
// produces an interesting interleaving, instrumented code voluntarily hands
// control back to a global Controller at semantic points (permission checks,
// balance reads, write-backs, ...). The Controller runs exactly one goroutine
// at a time and a Decider picks the next goroutine to resume. Every decision is
// recorded, so any failing run can be replayed bit-for-bit with ReplayDecider.
//
// This catches atomicity violations that have NO data race (and therefore are
// invisible to `go test -race`): duplicate coupon redemption, TOCTOU on
// permission checks, lost updates on read-modify-write state, etc.
package sct

import (
	"context"
	"fmt"
	"os"
	"sync"
)

// debugSched logs every scheduling decision when SCT_DEBUG=1, which turns an
// otherwise opaque deadlock into a readable last-decision trail.
var debugSched = os.Getenv("SCT_DEBUG") == "1"

func dbg(format string, args ...any) {
	if debugSched {
		fmt.Fprintf(os.Stderr, "sct-dbg: "+format+"\n", args...)
	}
}

// gidKey is the unexported context key carrying a goroutine id.
type gidKey struct{}

// ErrTickBudget is returned when a run exceeds its point-hit budget, which
// usually means a liveness bug (infinite loop) or a workload that does more
// work than the configured exploration bound.
var ErrTickBudget = fmt.Errorf("sct: tick budget exhausted")

// errHalt is the private sentinel panicked inside an instrumented goroutine to
// unwind its business code after the controller decides exploration is over
// (script finished, replay finished, budget exhausted). Business code never
// observes it: the worker wrapper in Run recovers it.
var errHalt = fmt.Errorf("sct: halted by controller")

// Point kinds used by the trace and by window tracking.
const (
	KindEnter   = "enter"
	KindExit    = "exit"
	KindPoint   = "point"
	KindOpen    = "open"
	KindClose   = "close"
	KindCancel  = "cancel"
	KindMutate  = "mutate"
	KindBarrier = "barrier"
)

// TraceEntry is one scheduling-visible event in a run.
type TraceEntry struct {
	Seq   int    `json:"seq"`
	GID   int    `json:"gid"`
	Kind  string `json:"kind"`
	Point string `json:"point"`
	// Resource is set for window/mutate events and drives TOCTOU detection.
	Resource string `json:"resource,omitempty"`
	// Observed is the resource value observed at an open, or the new value at
	// a mutate. Empty for plain points.
	Observed string `json:"observed,omitempty"`
}

// Edge is a directed transition between instrumented points (PointA -> PointB
// on the same goroutine), used for edge-coverage accounting.
type Edge struct {
	From string
	To   string
}

// TOCTOUWindow is a check/use pair on one resource, attributed to one goroutine.
type TOCTOUWindow struct {
	GID      int    `json:"gid"`
	Resource string `json:"resource"`
	Open     string `json:"open_point"`
	Close    string `json:"close_point"`
	Observed string `json:"observed_value"`
	// Interfered is true when another goroutine mutated the resource while
	// this window was open. That is the structural signature of a TOCTOU bug;
	// whether it is exploitable is decided together with the workload oracle.
	Interfered bool `json:"interfered"`
}

// winMeta is the controller-internal mutable counterpart of TOCTOUWindow.
type winMeta struct {
	gid        int
	resource   string
	openPoint  string
	closePoint string
	observed   string
	interfered bool
}

// Decider picks which live goroutine runs next. Implementations MUST be
// deterministic given their seed/script, which is what makes runs replayable.
type Decider interface {
	// Decide returns the gid of the goroutine to resume next. live is the
	// ascending list of currently runnable gids. Returning a gid not in live
	// (or any non-nil error) terminates the run.
	Decide(e TraceEntry, live []int) (gid int, err error)
}

// Controller is one per Run. User code only touches it through the package-level
// functions (Tick, OpenWindow, ...) keyed off the context.
type Controller struct {
	mu sync.Mutex
	cv *sync.Cond

	decider Decider
	n       int
	tickCap int

	state     map[int]int // gid -> 0 waiting, 1 running, 2 done
	current   int         // gid holding the token, -1 when parked
	seq       int
	enterTurn int // next gid allowed to record its enter event

	trace []TraceEntry
	// openWins holds currently open check/use windows; a goroutine may hold
	// several windows at once as long as their resources differ.
	openWins   []*winMeta
	allWindows []TOCTOUWindow
	edges      map[Edge]struct{}
	// schedEdges are inter-goroutine transitions observed: every time the
	// token moves from gid A to gid B. They are the direct measure of which
	// interleavings were explored, unlike same-goroutine point edges.
	schedEdges map[[2]int]struct{}
	lastPoint  map[int]string

	err   error
	ticks int

	// schedule records every gid handed to a decider, in order. It is the
	// exact byte sequence ReplayDecider needs to reproduce the run.
	schedule []int
}

func newController(decider Decider, n, tickCap int) *Controller {
	c := &Controller{
		decider:    decider,
		n:          n,
		tickCap:    tickCap,
		state:      make(map[int]int, n),
		current:    -1,
		openWins:   nil,
		allWindows: nil,
		edges:      make(map[Edge]struct{}),
		schedEdges: map[[2]int]struct{}{},
		lastPoint:  make(map[int]string),
	}
	c.cv = sync.NewCond(&c.mu)
	return c
}

// Schedule returns the exact decider decision sequence of the run; feed it to
// NewReplayDecider to reproduce the run deterministically.
func (c *Controller) Schedule() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.schedule...)
}

// Trace returns the recorded event sequence (valid after Run completes).
func (c *Controller) Trace() []TraceEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]TraceEntry, len(c.trace))
	copy(out, c.trace)
	return out
}

// Windows returns all check/use windows observed during the run.
func (c *Controller) Windows() []TOCTOUWindow {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]TOCTOUWindow, len(c.allWindows))
	copy(out, c.allWindows)
	return out
}

// SchedEdges returns the set of observed goroutine-to-goroutine transitions.
func (c *Controller) SchedEdges() map[[2]int]struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[[2]int]struct{}, len(c.schedEdges))
	for k := range c.schedEdges {
		out[k] = struct{}{}
	}
	return out
}

// Edges returns the set of point-to-point edges observed.
func (c *Controller) Edges() map[Edge]struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[Edge]struct{}, len(c.edges))
	for e := range c.edges {
		out[e] = struct{}{}
	}
	return out
}

// record appends an event, updates edge coverage, and applies mutation
// interference to every open window on the same resource owned by other gids.
// Caller holds c.mu.
func (c *Controller) record(gid int, kind, point, resource, observed string) TraceEntry {
	c.seq++
	e := TraceEntry{Seq: c.seq, GID: gid, Kind: kind, Point: point, Resource: resource, Observed: observed}
	c.trace = append(c.trace, e)

	if kind == KindPoint || kind == KindOpen || kind == KindClose || kind == KindMutate {
		if prev, ok := c.lastPoint[gid]; ok {
			c.edges[Edge{From: prev, To: point}] = struct{}{}
		}
		c.lastPoint[gid] = point
	}
	if kind == KindMutate && resource != "" {
		for _, w := range c.openWins {
			if w.resource == resource && w.gid != gid {
				w.interfered = true
			}
		}
	}
	return e
}

// handoff is the single blocking primitive used by enter/tick/exit: the running
// goroutine records what it just did, asks the decider who runs next, parks
// itself (unless it kept the token), and waits to be re-elected. When exiting
// is true the goroutine is marked done first; in that case the decider cannot
// pick it again and the call returns cleanly instead of panicking when the run
// halts.
func (c *Controller) handoff(gid int, kind, point, resource, observed string, exiting bool) {
	c.mu.Lock()

	if exiting {
		c.state[gid] = 2
	}
	e := c.record(gid, kind, point, resource, observed)

	live := c.liveLocked()
	if len(live) == 0 {
		// Last goroutine leaves: nothing to schedule, the run is complete.
		c.current = -1
		c.cv.Broadcast()
		c.mu.Unlock()
		return
	}

	next, err := c.decider.Decide(e, live)
	dbg("handoff gid=%d event=%s/%s live=%v -> next=%d err=%v", gid, kind, point, live, next, err)
	if err != nil || !contains(live, next) {
		if err != nil {
			c.err = err
		} else {
			c.err = fmt.Errorf("sct: decider selected gid %d not in live set %v", next, live)
		}
		c.current = -1
		c.cv.Broadcast()
		c.mu.Unlock()
		if exiting {
			return
		}
		panic(errHalt)
	}

	c.schedule = append(c.schedule, next)
	if next != gid {
		c.schedEdges[[2]int{gid, next}] = struct{}{}
	}
	c.current = next
	c.state[next] = 1
	if next != gid && !exiting {
		// An exiting goroutine stays done (set at the top of this handoff);
		// resetting it to waiting would resurrect a dead goroutine in the
		// live set and deadlock every later decision that picks it.
		c.state[gid] = 0
	}
	c.cv.Broadcast()
	// An exiting goroutine can never be re-elected (its state is done), so it
	// must not wait for the token to come back — doing so deadlocks once the
	// last remaining goroutine also leaves.
	if exiting {
		c.mu.Unlock()
		return
	}
	for c.current != gid && c.err == nil {
		c.cv.Wait()
	}
	if c.err != nil {
		c.mu.Unlock()
		if exiting {
			return
		}
		panic(errHalt)
	}
	c.mu.Unlock()
}

// enter registers a worker goroutine and blocks until it is elected.
//
// Enters are serialized in gid order behind a turn counter, so the trace's
// enter events are always g0, g1, ... regardless of OS thread scheduling; that
// is what makes a recorded schedule replay to a bit-identical trace. Enters
// are NOT scheduling decisions: once every goroutine has registered, gid 0
// receives the token and every other gid parks until the decider elects it.
func (c *Controller) enter(gid int) {
	c.mu.Lock()
	// Phase 1: wait for registration turn in strict gid order.
	for c.enterTurn != gid && c.err == nil {
		c.cv.Wait()
	}
	if c.err != nil {
		c.mu.Unlock()
		panic(errHalt)
	}
	c.state[gid] = 0
	c.record(gid, KindEnter, fmt.Sprintf("g%d.enter", gid), "", "")
	c.enterTurn++
	c.cv.Broadcast()

	if gid != c.n-1 {
		// Phase 2: wait until the last goroutine has registered, then park.
		for c.enterTurn < c.n && c.err == nil {
			c.cv.Wait()
		}
		if c.err != nil {
			c.mu.Unlock()
			panic(errHalt)
		}
		for c.current != gid && c.err == nil {
			c.cv.Wait()
		}
		if c.err != nil {
			c.mu.Unlock()
			panic(errHalt)
		}
		c.mu.Unlock()
		return
	}

	// Last goroutine flips the run into scheduling mode and hands the token
	// deterministically to gid 0; it then parks like every other non-zero gid.
	c.current = 0
	c.state[0] = 1
	c.cv.Broadcast()
	if gid != 0 {
		for c.current != gid && c.err == nil {
			c.cv.Wait()
		}
		if c.err != nil {
			c.mu.Unlock()
			panic(errHalt)
		}
	}
	c.mu.Unlock()
}

func (c *Controller) exit(gid int) {
	c.handoff(gid, KindExit, fmt.Sprintf("g%d.exit", gid), "", "", true)
}

func (c *Controller) tick(gid int, point string) {
	c.mu.Lock()
	c.ticks++
	if c.ticks > c.tickCap {
		c.err = ErrTickBudget
		c.current = -1
		c.cv.Broadcast()
		c.mu.Unlock()
		panic(errHalt)
	}
	c.mu.Unlock()
	c.handoff(gid, KindPoint, point, "", "", false)
}

func (c *Controller) openWindow(gid int, point, resource, observed string) {
	c.mu.Lock()
	w := &winMeta{
		gid:       gid,
		resource:  resource,
		openPoint: point,
		observed:  observed,
	}
	c.openWins = append(c.openWins, w)
	c.mu.Unlock()
	c.handoff(gid, KindOpen, point, resource, observed, false)
}

func (c *Controller) closeWindow(gid int, point, resource string) {
	c.mu.Lock()
	c.openWins = removeWindow(c.openWins, func(w *winMeta) bool {
		if w.gid != gid || w.resource != resource {
			return false
		}
		c.allWindows = append(c.allWindows, TOCTOUWindow{
			GID: w.gid, Resource: w.resource, Open: w.openPoint,
			Close: point, Observed: w.observed, Interfered: w.interfered,
		})
		return true
	})
	c.mu.Unlock()
	c.handoff(gid, KindClose, point, resource, "", false)
}

func (c *Controller) cancelWindow(gid int, point, resource string) {
	c.mu.Lock()
	c.openWins = removeWindow(c.openWins, func(w *winMeta) bool {
		if w.gid != gid || w.resource != resource {
			return false
		}
		c.allWindows = append(c.allWindows, TOCTOUWindow{
			GID: w.gid, Resource: w.resource, Open: w.openPoint,
			Close: "cancelled:" + point, Observed: w.observed, Interfered: w.interfered,
		})
		return true
	})
	c.mu.Unlock()
	c.handoff(gid, KindCancel, point, resource, "", false)
}

func (c *Controller) mutate(gid int, point, resource, newVal string) {
	c.handoff(gid, KindMutate, point, resource, newVal, false)
}

// ---- context plumbing -------------------------------------------------------

// WithGID returns a context carrying a worker goroutine id. The worker
// functions spawned by Run receive this automatically; handler/store code that
// spawns its own helper goroutines should propagate the context so ticks keep
// the right attribution.
func WithGID(ctx context.Context, gid int) context.Context {
	return context.WithValue(ctx, gidKey{}, gid)
}

// GID extracts the worker goroutine id from the context. Returns -1 when the
// code is running outside an sct run, in which case all instrumented calls are
// no-ops: the same instrumented binary runs unmodified in production.
func GID(ctx context.Context) int {
	if v, ok := ctx.Value(gidKey{}).(int); ok {
		return v
	}
	return -1
}

func controllerFrom(ctx context.Context) *Controller {
	c, _ := ctx.Value(controllerKey{}).(*Controller)
	return c
}

type controllerKey struct{}

func withController(ctx context.Context, c *Controller) context.Context {
	return context.WithValue(ctx, controllerKey{}, c)
}

// Tick yields to the scheduler at a plain semantic point (e.g. "after auth
// check", "before write-back"). Outside an sct run it is a no-op.
//
// Placement rule: put ticks OUTSIDE locks/critical sections. A tick inside a
// lock that another goroutine needs serializes the exploration into one
// interleaving and hides the bug you are looking for.
func Tick(ctx context.Context, point string) {
	if c := controllerFrom(ctx); c != nil {
		gid := GID(ctx)
		if gid < 0 {
			return
		}
		c.tick(gid, point)
	}
}

// OpenWindow marks the "check" side of a check/use pair: the goroutine has
// observed value `observed` of `resource` and will later act on that
// observation at CloseWindow. A mutation of the same resource by another
// goroutine before the close marks the window interfered.
func OpenWindow(ctx context.Context, point, resource, observed string) {
	if c := controllerFrom(ctx); c != nil {
		if gid := GID(ctx); gid >= 0 {
			c.openWindow(gid, point, resource, observed)
		}
	}
}

// CloseWindow marks the "use" side of a check/use pair.
func CloseWindow(ctx context.Context, point, resource string) {
	if c := controllerFrom(ctx); c != nil {
		if gid := GID(ctx); gid >= 0 {
			c.closeWindow(gid, point, resource)
		}
	}
}

// CancelWindow closes a check/use pair whose "use" was skipped (e.g. the
// permission check failed and the request returned early).
func CancelWindow(ctx context.Context, point, resource string) {
	if c := controllerFrom(ctx); c != nil {
		if gid := GID(ctx); gid >= 0 {
			c.cancelWindow(gid, point, resource)
		}
	}
}

// Mutate records a write to a shared resource. It is the event that interferes
// with other goroutines' open check/use windows.
func Mutate(ctx context.Context, point, resource, newVal string) {
	if c := controllerFrom(ctx); c != nil {
		if gid := GID(ctx); gid >= 0 {
			c.mutate(gid, point, resource, newVal)
		}
	}
}

func contains(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// removeWindow drops every element for which match returns true.
func removeWindow(ws []*winMeta, match func(*winMeta) bool) []*winMeta {
	kept := ws[:0]
	for _, w := range ws {
		if !match(w) {
			kept = append(kept, w)
		}
	}
	return kept
}

func (c *Controller) liveLocked() []int {
	out := make([]int, 0, len(c.state))
	for gid := 0; gid < c.n; gid++ {
		if c.state[gid] == 0 || c.state[gid] == 1 {
			out = append(out, gid)
		}
	}
	return out
}
