package proxy

import (
	"sync"
	"time"
)

// ApprovalKey uniquely identifies a pending or granted approval.
type ApprovalKey struct {
	AgentID   string `json:"agent_id"`
	SecretKey string `json:"secret_key"`
	Domain    string `json:"domain"`
	Method    string `json:"method"`
}

// approvalWaiter holds a channel that a blocked request goroutine waits on.
type approvalWaiter struct {
	ch        chan bool
	createdAt time.Time
}

// ApprovalStore tracks both granted session approvals and requests currently
// waiting for a developer decision. Blocked proxy requests call WaitForApproval
// and hold their HTTP connection open. The proxy terminal (or /approve endpoint)
// calls Approve/Deny to unblock them immediately — no polling required.
type ApprovalStore struct {
	mu      sync.RWMutex
	granted map[ApprovalKey]time.Time
	pending map[ApprovalKey][]*approvalWaiter
	// notify receives a key whenever a new waiter registers,
	// so the interactive approval goroutine can print a prompt.
	notify chan ApprovalKey
}

// NewApprovalStore creates a ready-to-use ApprovalStore.
// notifyBuf sets the channel buffer size; use 0 for unbuffered (blocks sender
// if nothing is reading) or ≥1 for a non-blocking notification pattern.
func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{
		granted: make(map[ApprovalKey]time.Time),
		pending: make(map[ApprovalKey][]*approvalWaiter),
		notify:  make(chan ApprovalKey, 32),
	}
}

// Notifications returns the channel that receives a key each time a new
// request starts waiting. Read from this in the proxy terminal goroutine
// to show interactive approval prompts.
func (s *ApprovalStore) Notifications() <-chan ApprovalKey {
	return s.notify
}

// IsApproved reports whether the key has already been granted (non-blocking).
func (s *ApprovalStore) IsApproved(k ApprovalKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.granted[k]
	return exists
}

// WaitForApproval blocks until the key is approved, denied, or the timeout
// elapses. Returns true only if explicitly approved.
//
// The caller (a proxy request goroutine) holds its HTTP connection open while
// waiting; the connection is released the moment Approve or Deny is called.
func (s *ApprovalStore) WaitForApproval(k ApprovalKey, timeout time.Duration) bool {
	// Fast path: already granted.
	s.mu.RLock()
	if _, exists := s.granted[k]; exists {
		s.mu.RUnlock()
		return true
	}
	s.mu.RUnlock()

	// Register a waiter channel.
	w := &approvalWaiter{
		ch:        make(chan bool, 1),
		createdAt: time.Now(),
	}
	s.mu.Lock()
	s.pending[k] = append(s.pending[k], w)
	s.mu.Unlock()

	// Non-blocking notify to the interactive goroutine.
	select {
	case s.notify <- k:
	default:
		// channel full — the goroutine will still discover the pending key
		// via ListPending on its next iteration.
	}

	select {
	case result := <-w.ch:
		return result
	case <-time.After(timeout):
		s.removeWaiter(k, w)
		return false
	}
}

// Approve grants the key for this session and unblocks all waiting requests.
func (s *ApprovalStore) Approve(k ApprovalKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted[k] = time.Now()
	for _, w := range s.pending[k] {
		select {
		case w.ch <- true:
		default:
		}
	}
	delete(s.pending, k)
}

// Deny rejects all waiting requests for this key (does NOT persist — next
// request for the same key will prompt again).
func (s *ApprovalStore) Deny(k ApprovalKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.pending[k] {
		select {
		case w.ch <- false:
		default:
		}
	}
	delete(s.pending, k)
}

// ListPending returns a deduplicated snapshot of keys currently waiting.
// Used by the interactive approval goroutine to catch any keys it missed
// on the notify channel.
func (s *ApprovalStore) ListPending() []ApprovalKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]ApprovalKey, 0, len(s.pending))
	for k, waiters := range s.pending {
		if len(waiters) > 0 {
			keys = append(keys, k)
		}
	}
	return keys
}

// removeWaiter cleans up a timed-out waiter from the pending map.
func (s *ApprovalStore) removeWaiter(k ApprovalKey, target *approvalWaiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	waiters := s.pending[k]
	for i, w := range waiters {
		if w == target {
			s.pending[k] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(s.pending[k]) == 0 {
		delete(s.pending, k)
	}
}
