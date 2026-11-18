package sampleservice

import (
	"context"

	"sctlab/sct"
)

// Each workload is a concrete concurrent request scenario. State is rebuilt on
// every run via Setup, so every schedule starts from identical conditions and
// replays deterministically.

// ---------------------------------------------------------------- coupons ---

type CouponState struct {
	Svc *Service
	Out *outcomes
}

type CouponWorkload struct{ Mode Mode }

func (CouponWorkload) Name() string { return "coupon-double-redeem" }
func (CouponWorkload) N() int       { return 2 }

func (w CouponWorkload) Setup() sct.State {
	return &CouponState{Svc: NewService(w.Mode), Out: newOutcomes(2)}
}

func (w CouponWorkload) Worker(ctx context.Context, gid int, st sct.State) error {
	s := st.(*CouponState)
	err := s.Svc.Coupons.Redeem(ctx, gid, "C1")
	s.Out.record(gid, err)
	return nil
}

func (CouponWorkload) Points() []string {
	return []string{
		"coupon.redeem.check", "coupon.redeem.after_check",
		"coupon.redeem.write", "coupon.redeem.commit", "coupon.redeem.reject",
	}
}

func (w CouponWorkload) Oracle(st sct.State, trace []sct.TraceEntry, windows []sct.TOCTOUWindow) []sct.Violation {
	s := st.(*CouponState)
	var vs []sct.Violation

	// Invariant oracle: a single-use coupon may be redeemed at most once.
	if n := s.Out.successCount(); n > 1 {
		vs = append(vs, sct.Violation{
			Rule: "coupon-single-redemption", Kind: "invariant", Resource: "C1",
			GIDs:    successGIDs(s.Out),
			Message: "coupon C1 redeemed by multiple concurrent requests",
		})
	}
	if c := s.Svc.Coupons.Snapshot()["C1"]; c.Redeemed && s.Out.successCount() > 1 {
		vs = append(vs, sct.Violation{
			Rule: "coupon-state-vs-responses", Kind: "invariant", Resource: "C1",
			GIDs:    successGIDs(s.Out),
			Message: "stored owner disagrees with the number of successful redeem responses",
		})
	}
	// Structural oracle: any interfered check/use window on a coupon is itself
	// suspicious even if the invariant happened to survive this run.
	for _, win := range windows {
		if win.Interfered && win.Resource == couponResource("C1") {
			vs = append(vs, sct.Violation{
				Rule: "coupon-toctou-window", Kind: "toctou", Resource: "C1",
				GIDs:    []int{win.GID},
				Message: "redemption decision was invalidated by another request before commit",
			})
		}
	}
	return dedupViolations(vs)
}

// CouponAttackScript is the hand-encoded exploit for the incident: both
// requests pass the check before either commits. Gid-only steps keep the script
// stable across point renames; point expectations are validated separately in
// the unit tests.
func CouponAttackScript() sct.NamedScript {
	return sct.NamedScript{
		Label: "both-checks-before-any-commit",
		Steps: []sct.ScriptStep{
			{GID: 0}, // g0: enter -> check -> park at after_check
			{GID: 1}, // g1: enter -> check -> park at after_check
			{GID: 0}, // g0: commit first redemption
		},
		// fallback then lets g1 commit its stale decision -> double redeem
	}
}

// ------------------------------------------------------------- permissions ---

type PermissionState struct {
	Svc *Service
	Out *outcomes
}

type PermissionWorkload struct{ Mode Mode }

func (PermissionWorkload) Name() string { return "permission-revoke-toctou" }
func (PermissionWorkload) N() int       { return 2 }

func (w PermissionWorkload) Setup() sct.State {
	return &PermissionState{Svc: NewService(w.Mode), Out: newOutcomes(2)}
}

func (w PermissionWorkload) Worker(ctx context.Context, gid int, st sct.State) error {
	s := st.(*PermissionState)
	var err error
	if gid == 0 {
		// The request whose permission is about to be revoked.
		err = s.Svc.Perms.DoAdminAction(ctx, gid, 1, "delete-tenant")
	} else {
		// The concurrent admin request revoking user 1.
		s.Svc.Perms.Revoke(ctx, 1)
	}
	s.Out.record(gid, err)
	return nil
}

func (PermissionWorkload) Points() []string {
	return []string{
		"admin.check", "admin.after_check", "admin.commit", "admin.deny",
		"perm.revoke", "perm.revoke.done",
	}
}

func (w PermissionWorkload) Oracle(st sct.State, trace []sct.TraceEntry, windows []sct.TOCTOUWindow) []sct.Violation {
	s := st.(*PermissionState)
	var vs []sct.Violation
	res := permResource(1)

	// Ordering index: position of the revoke mutation and each privileged use
	// in the global event stream.
	revokeSeq := -1
	useSeq := -1
	for _, e := range trace {
		if e.Kind == sct.KindMutate && e.Resource == res {
			revokeSeq = e.Seq
		}
		if e.Kind == sct.KindClose && e.Resource == res {
			useSeq = e.Seq
		}
	}

	for _, en := range s.Svc.Perms.AuditSnapshot() {
		// Ordering oracle: a privileged use is only a violation when the
		// revoke already happened before the use. Use-before-revoke is a
		// perfectly legal serial order and must not be flagged.
		if revokeSeq >= 0 && useSeq >= 0 && revokeSeq < useSeq {
			vs = append(vs, sct.Violation{
				Rule: "authz-use-after-revoke-ordering", Kind: "invariant",
				Resource: res, GIDs: []int{en.GID},
				Message: "privileged use committed after an observed revoke event (ordering proven via trace)",
			})
		}
		if !en.SeenAt {
			vs = append(vs, sct.Violation{
				Rule: "authz-stale-check", Kind: "invariant",
				Resource: res, GIDs: []int{en.GID},
				Message: "action executed on a check result that was already false at commit time",
			})
		}
	}
	for _, win := range windows {
		if win.Interfered && win.Resource == res {
			vs = append(vs, sct.Violation{
				Rule: "authz-toctou-window", Kind: "toctou",
				Resource: res, GIDs: []int{win.GID},
				Message: "permission result was revoked between check and privileged use",
			})
		}
	}
	return dedupViolations(vs)
}

// PermissionAttackScript: the admin request fully passes its check, then the
// revoke commits, then the now-unprivileged request still performs the action.
func PermissionAttackScript() sct.NamedScript {
	return sct.NamedScript{
		Label: "check-then-revoke-then-use",
		Steps: []sct.ScriptStep{
			{GID: 0}, // g0: check -> park at after_check
			{GID: 1}, // g1: enter, revoke lands inside g0's open window
		},
		// fallback resumes g0, which commits the privileged action anyway
	}
}

// ----------------------------------------------------------------- accounts ---

type AccountState struct {
	Svc      *Service
	Out      *outcomes
	StartBal int
}

type AccountWorkload struct{ Mode Mode }

func (AccountWorkload) Name() string { return "account-lost-update" }
func (AccountWorkload) N() int       { return 2 }

func (w AccountWorkload) Setup() sct.State {
	svc := NewService(w.Mode)
	return &AccountState{Svc: svc, Out: newOutcomes(2), StartBal: svc.Accounts.Balance("A1")}
}

func (w AccountWorkload) Worker(ctx context.Context, gid int, st sct.State) error {
	s := st.(*AccountState)
	// Two debits of 60 against a balance of 100: at most one may succeed in
	// any serializable execution.
	err := s.Svc.Accounts.Debit(ctx, gid, "A1", 60)
	s.Out.record(gid, err)
	return nil
}

func (AccountWorkload) Points() []string {
	return []string{
		"acct.debit.read", "acct.debit.after_read",
		"acct.debit.write", "acct.debit.commit", "acct.debit.reject",
	}
}

func (w AccountWorkload) Oracle(st sct.State, trace []sct.TraceEntry, windows []sct.TOCTOUWindow) []sct.Violation {
	s := st.(*AccountState)
	var vs []sct.Violation
	ledger := s.Svc.Accounts.LedgerSnapshot()
	final := s.Svc.Accounts.Balance("A1")

	// Invariant oracle: the ledger must be explainable by some serial order of
	// the same debits against the starting balance.
	committed := 0
	for _, e := range ledger {
		committed += e.Amount
	}
	if s.StartBal-committed != final {
		vs = append(vs, sct.Violation{
			Rule: "acct-balance-ledger-consistency", Kind: "serializability", Resource: "A1",
			GIDs:    ledgerGIDs(ledger),
			Message: "final balance does not equal start balance minus committed ledger (lost update)",
		})
	}
	// Serializability oracle: with two 60-debits on 100, no serial schedule
	// admits two successes.
	if s.Out.successCount() > 1 {
		vs = append(vs, sct.Violation{
			Rule: "acct-no-serial-equivalent", Kind: "serializability", Resource: "A1",
			GIDs:    successGIDs(s.Out),
			Message: "two debits both succeeded although no serial ordering admits both",
		})
	}
	if final < 0 {
		vs = append(vs, sct.Violation{
			Rule: "acct-nonnegative", Kind: "invariant", Resource: "A1",
			GIDs: ledgerGIDs(ledger), Message: "balance went negative",
		})
	}
	for _, win := range windows {
		if win.Interfered && win.Resource == acctResource("A1") {
			vs = append(vs, sct.Violation{
				Rule: "acct-toctou-window", Kind: "toctou", Resource: "A1",
				GIDs:    []int{win.GID},
				Message: "debit decision based on a balance another request changed before commit",
			})
		}
	}
	return dedupViolations(vs)
}

// AccountAttackScript: both debits read 100, then both write back 40.
func AccountAttackScript() sct.NamedScript {
	return sct.NamedScript{
		Label: "both-reads-before-any-write",
		Steps: []sct.ScriptStep{
			{GID: 0}, // g0: read -> park at after_read
			{GID: 1}, // g1: read -> park at after_read
			{GID: 0}, // g0: writes back from its stale read
		},
		// fallback lets g1 write back too -> lost update
	}
}

// ------------------------------------------------------------------- helpers ---

func successGIDs(o *outcomes) []int {
	o.mu.Lock()
	defer o.mu.Unlock()
	var gids []int
	for gid := range o.ok {
		gids = append(gids, gid)
	}
	return gids
}

func ledgerGIDs(ls []LedgerEntry) []int {
	seen := map[int]bool{}
	var gids []int
	for _, e := range ls {
		if !seen[e.GID] {
			seen[e.GID] = true
			gids = append(gids, e.GID)
		}
	}
	return gids
}

func dedupViolations(vs []sct.Violation) []sct.Violation {
	seen := map[string]bool{}
	var out []sct.Violation
	for _, v := range vs {
		key := v.Rule + "|" + v.Resource
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	return out
}
