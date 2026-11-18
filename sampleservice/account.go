package sampleservice

import (
	"context"
	"strconv"
	"sync"

	"sctlab/sct"
)

// Account is a balance that debit requests read-modify-write.
type Account struct {
	ID      string
	Balance int
}

// AccountStore backs POST /accounts/:id/debit.
//
// Buggy variant: the balance read and the conditional write-back are separate
// locked DAO calls. Two debits each read 100, each decide they are covered,
// and both write back their own result — one update is silently lost.
type AccountStore struct {
	mode Mode
	mu   sync.Mutex
	rows map[string]*Account
	// ledger records every committed debit for serializability analysis.
	ledger []LedgerEntry
}

type LedgerEntry struct {
	GID    int
	Amount int
}

func NewAccountStore(mode Mode) *AccountStore {
	return &AccountStore{
		mode: mode,
		rows: map[string]*Account{"A1": {ID: "A1", Balance: 100}},
	}
}

func acctResource(id string) string { return "account:" + id }

// Debit attempts to charge amount against the account.
func (s *AccountStore) Debit(ctx context.Context, gid int, id string, amount int) error {
	res := acctResource(id)

	if s.mode == ModeBuggy {
		balance := s.readBalance(id)
		sct.OpenWindow(ctx, "acct.debit.read", res, strconv.Itoa(balance))
		if balance < amount {
			sct.CancelWindow(ctx, "acct.debit.reject", res)
			return ErrInsufficient
		}
		sct.Tick(ctx, "acct.debit.after_read")

		next := balance - amount // computed from the stale read
		s.writeBalance(id, next)
		s.appendLedger(gid, amount)
		sct.Mutate(ctx, "acct.debit.write", res, strconv.Itoa(next))
		sct.CloseWindow(ctx, "acct.debit.commit", res)
		return nil
	}

	// --- fixed: read, decide and write in one critical section ---
	s.mu.Lock()
	acc := s.rows[id]
	if acc.Balance < amount {
		s.mu.Unlock()
		sct.Tick(ctx, "acct.debit.reject")
		return ErrInsufficient
	}
	acc.Balance -= amount
	s.ledger = append(s.ledger, LedgerEntry{GID: gid, Amount: amount})
	newBal := acc.Balance
	s.mu.Unlock()

	sct.Mutate(ctx, "acct.debit.write", res, strconv.Itoa(newBal))
	sct.Tick(ctx, "acct.debit.commit")
	return nil
}

func (s *AccountStore) readBalance(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows[id].Balance
}

func (s *AccountStore) writeBalance(id string, v int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[id].Balance = v
}

func (s *AccountStore) appendLedger(gid, amount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ledger = append(s.ledger, LedgerEntry{GID: gid, Amount: amount})
}

func (s *AccountStore) Balance(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows[id].Balance
}

// LedgerSnapshot copies committed debits; used by the serializability oracle.
func (s *AccountStore) LedgerSnapshot() []LedgerEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LedgerEntry, len(s.ledger))
	copy(out, s.ledger)
	return out
}
