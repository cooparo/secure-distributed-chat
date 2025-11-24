package session

import (
	"sync"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[identity.IdentityAddress]*Session
	address  identity.IdentityAddress
}

func NewSessionManager(address identity.IdentityAddress) *SessionManager {
	return &SessionManager{
		sessions: make(map[identity.IdentityAddress]*Session),
		address:  address,
	}
}

func (m *SessionManager) Get(address identity.IdentityAddress) (*Session, bool) {
	m.mu.RLock()
	s, ok := m.sessions[address]
	m.mu.RUnlock()
	return s, ok
}

func (m *SessionManager) Set(address identity.IdentityAddress, s *Session) {
	m.mu.Lock()
	m.sessions[address] = s
	m.mu.Unlock()
}

func (m *SessionManager) Delete(address identity.IdentityAddress) {
	m.mu.Lock()
	delete(m.sessions, address)
	m.mu.Unlock()
}

func (m *SessionManager) Address() identity.IdentityAddress {
	return m.address
}
