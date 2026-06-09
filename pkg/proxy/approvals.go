package proxy

import (
	"sync"
	"time"
)

type ApprovalKey struct {
	AgentID   string `json:"agent_id"`
	SecretKey string `json:"secret_key"`
	Domain    string `json:"domain"`
	Method    string `json:"method"`
}

type ApprovalStore struct {
	mu       sync.RWMutex
	approved map[ApprovalKey]time.Time
}

func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{
		approved: make(map[ApprovalKey]time.Time),
	}
}

func (s *ApprovalStore) IsApproved(k ApprovalKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.approved[k]
	return exists
}

func (s *ApprovalStore) Approve(k ApprovalKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approved[k] = time.Now()
}
