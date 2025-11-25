package session

import (
	"sync"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type SessionManager struct {
	mu               sync.RWMutex
	sessions         map[string]*Session
	Address          identity.IdentityAddress
	PrivateKeyBundle *identity.PrivateKeyBundle
}

// Make a new session manager.
// Expects both address and privKeyBundle has been validated.
func NewSessionManager(address identity.IdentityAddress, privKeyBundle *identity.PrivateKeyBundle) *SessionManager {
	return &SessionManager{
		sessions:         make(map[string]*Session),
		Address:          address,
		PrivateKeyBundle: privKeyBundle,
	}
}

func (m *SessionManager) Get(key string) (*Session, bool) {
	m.mu.RLock()
	s, ok := m.sessions[key]
	m.mu.RUnlock()
	return s, ok
}

func (m *SessionManager) Set(key string, s *Session) {
	m.mu.Lock()
	m.sessions[key] = s
	m.mu.Unlock()
}

func (m *SessionManager) Delete(key string) {
	m.mu.Lock()
	delete(m.sessions, key)
	m.mu.Unlock()
}
