package session

import (
	"sync"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[identity.IdentityAddress]*Session
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[identity.IdentityAddress]*Session),
	}
}

func (m *SessionManager) Get(addr identity.IdentityAddress) (*Session, bool) {
	m.mu.RLock()
	s, ok := m.sessions[addr]
	m.mu.RUnlock()
	return s, ok
}

func (m *SessionManager) Set(addr identity.IdentityAddress, s *Session) {
	m.mu.Lock()
	m.sessions[addr] = s
	m.mu.Unlock()
}

func (m *SessionManager) Delete(addr identity.IdentityAddress) {
	m.mu.Lock()
	delete(m.sessions, addr)
	m.mu.Unlock()
}

// TODO: SessionManager.SaveAll() method to store in database
