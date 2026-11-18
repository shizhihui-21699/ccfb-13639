// Package sampleservice is a deliberately small request-handling service that
// embeds three classes of concurrency defects, each in two variants:
//
//   - ModeBuggy:  per-DAO-call locking. Every individual read/write is
//     synchronized, so `go test -race` stays silent, but the check/use
//     sequence spans no lock and can be interleaved across requests.
//   - ModeAtomic: the whole check/use decision runs under one critical
//     section (or an atomic re-check), closing the interleaving window.
//
// All store methods take a context and call sct instrumentation points. In
// production (no sct controller in the context) those calls are no-ops, so the
// same binary runs unchanged.
package sampleservice

import (
	"errors"
	"sync"
)

// Mode selects the buggy or fixed implementation.
type Mode int

const (
	ModeBuggy Mode = iota
	ModeAtomic
)

func (m Mode) String() string {
	if m == ModeAtomic {
		return "atomic"
	}
	return "buggy"
}

var (
	ErrAlreadyRedeemed = errors.New("coupon already redeemed")
	ErrForbidden       = errors.New("forbidden")
	ErrInsufficient    = errors.New("insufficient funds")
)

// Service bundles the three stores under one mode switch.
type Service struct {
	Mode Mode

	Coupons  *CouponStore
	Perms    *PermissionStore
	Accounts *AccountStore
}

func NewService(mode Mode) *Service {
	return &Service{
		Mode:     mode,
		Coupons:  NewCouponStore(mode),
		Perms:    NewPermissionStore(mode),
		Accounts: NewAccountStore(mode),
	}
}

// outcome records what one request goroutine did, indexed by gid, so the
// workload oracle can judge per-request results against final state.
type outcomes struct {
	mu  sync.Mutex
	ok  map[int]bool
	err map[int]string
}

func newOutcomes(n int) *outcomes {
	return &outcomes{ok: map[int]bool{}, err: map[int]string{}}
}

func (o *outcomes) record(gid int, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err == nil {
		o.ok[gid] = true
		return
	}
	o.err[gid] = err.Error()
}

func (o *outcomes) successCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.ok)
}
