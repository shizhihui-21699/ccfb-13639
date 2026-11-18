package sampleservice

import (
	"context"
	"strconv"
	"sync"

	"sctlab/sct"
)

// AuditEntry records one privileged action. SeenAt is the admin flag value
// captured at execution time — the oracle compares it against the check-time
// decision.
type AuditEntry struct {
	GID    int
	Action string
	SeenAt bool
}

// PermissionStore is the ACL behind any admin-only endpoint.
//
// Buggy variant (the second production incident): IsAdmin is evaluated when
// the request enters the handler, but the privileged write happens later.
// Revoking the permission in between still lets the request through — a classic
// TOCTOU. Again every map access is locked, so there is no data race to find.
type PermissionStore struct {
	mode Mode
	mu   sync.RWMutex
	// admins[user] = currently admin?
	admins map[int]bool
	audit  []AuditEntry
}

func NewPermissionStore(mode Mode) *PermissionStore {
	return &PermissionStore{
		mode:   mode,
		admins: map[int]bool{1: true, 2: true},
	}
}

func permResource(user int) string { return "perm:user" + strconv.Itoa(user) }

// IsAdmin is the check-side DAO call.
func (s *PermissionStore) IsAdmin(user int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.admins[user]
}

// Revoke drops a user's admin grant (the concurrent "permission revoked"
// request).
func (s *PermissionStore) Revoke(ctx context.Context, user int) {
	s.mu.Lock()
	s.admins[user] = false
	s.mu.Unlock()
	sct.Mutate(ctx, "perm.revoke", permResource(user), "false")
	sct.Tick(ctx, "perm.revoke.done")
}

// DoAdminAction runs a privileged action after re-checking permission
// according to the active mode.
func (s *PermissionStore) DoAdminAction(ctx context.Context, gid, user int, action string) error {
	res := permResource(user)

	if s.mode == ModeBuggy {
		allowed := s.IsAdmin(user)
		sct.OpenWindow(ctx, "admin.check", res, strconv.FormatBool(allowed))
		if !allowed {
			sct.CancelWindow(ctx, "admin.deny", res)
			return ErrForbidden
		}
		// Handler does unrelated work / network calls here; revocation can
		// land in this window.
		sct.Tick(ctx, "admin.after_check")

		s.mu.RLock()
		seen := s.admins[user]
		s.audit = append(s.audit, AuditEntry{GID: gid, Action: action, SeenAt: seen})
		s.mu.RUnlock()
		sct.CloseWindow(ctx, "admin.commit", res)
		return nil
	}

	// --- fixed: re-check and act inside one critical section ---
	s.mu.Lock()
	if !s.admins[user] {
		s.mu.Unlock()
		sct.Tick(ctx, "admin.deny")
		return ErrForbidden
	}
	s.audit = append(s.audit, AuditEntry{GID: gid, Action: action, SeenAt: true})
	s.mu.Unlock()
	sct.Tick(ctx, "admin.commit")
	return nil
}

// AuditSnapshot copies the privileged-action log for oracle assertions.
func (s *PermissionStore) AuditSnapshot() []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEntry, len(s.audit))
	copy(out, s.audit)
	return out
}

// AdminSnapshot copies the current ACL.
func (s *PermissionStore) AdminSnapshot() map[int]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[int]bool, len(s.admins))
	for k, v := range s.admins {
		out[k] = v
	}
	return out
}
