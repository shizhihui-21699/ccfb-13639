package sampleservice

import (
	"context"
	"strconv"
	"sync"

	"sctlab/sct"
)

// Coupon models a single-use coupon.
type Coupon struct {
	ID       string
	Redeemed bool
	Owner    int // gid that redeemed it; -1 when unused
}

// CouponStore is the DAO behind POST /coupons/:id/redeem.
//
// Buggy variant (the production incident): Redeemed check and the redeem write
// are two separate lock-protected calls. Each call is race-free, but two
// requests can both observe Redeemed=false before either writes true.
type CouponStore struct {
	mode Mode
	mu   sync.Mutex
	rows map[string]*Coupon
}

func NewCouponStore(mode Mode) *CouponStore {
	return &CouponStore{
		mode: mode,
		rows: map[string]*Coupon{"C1": {ID: "C1", Redeemed: false, Owner: -1}},
	}
}

// Resource naming convention for TOCTOU windows and mutation events.
func couponResource(id string) string { return "coupon:" + id }

// Redeem processes one redemption request.
func (s *CouponStore) Redeem(ctx context.Context, gid int, id string) error {
	res := couponResource(id)

	if s.mode == ModeBuggy {
		// --- check: separate, individually-locked DAO read ---
		observed := s.lookupRedeemed(id)
		sct.OpenWindow(ctx, "coupon.redeem.check", res, strconv.FormatBool(observed))
		if observed {
			sct.CancelWindow(ctx, "coupon.redeem.reject", res)
			return ErrAlreadyRedeemed
		}
		// No lock is held here: another request's write can land in this gap.
		sct.Tick(ctx, "coupon.redeem.after_check")

		// --- use: separate, individually-locked DAO write ---
		s.markRedeemed(id, gid)
		// Mutation is emitted while the other goroutine's window is still
		// open; only afterwards do we close our own check/use window.
		sct.Mutate(ctx, "coupon.redeem.write", res, "true")
		sct.CloseWindow(ctx, "coupon.redeem.commit", res)
		return nil
	}

	// --- fixed: the decision and the write are one atomic step ---
	s.mu.Lock()
	c := s.rows[id]
	if c.Redeemed {
		s.mu.Unlock()
		// Instrument the rejected path too, so edge coverage sees both.
		sct.Tick(ctx, "coupon.redeem.reject")
		return ErrAlreadyRedeemed
	}
	c.Redeemed = true
	c.Owner = gid
	s.mu.Unlock()

	sct.Mutate(ctx, "coupon.redeem.write", res, "true")
	sct.Tick(ctx, "coupon.redeem.commit")
	return nil
}

func (s *CouponStore) lookupRedeemed(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows[id].Redeemed
}

func (s *CouponStore) markRedeemed(id string, gid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.rows[id]
	c.Redeemed = true
	c.Owner = gid
}

// Snapshot returns a copy of the coupon table for oracle assertions.
func (s *CouponStore) Snapshot() map[string]Coupon {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Coupon, len(s.rows))
	for id, c := range s.rows {
		out[id] = *c
	}
	return out
}
