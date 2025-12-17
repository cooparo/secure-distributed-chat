package session

import (
	"net"
	"sync"
	"time"

	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type SessionManager struct {
	mu                  sync.RWMutex
	sessions            map[string]*Session
	Address             identity.IdentityAddress
	PrivateKeyBundle    *identity.PrivateKeyBundle
	SignedKeyBundle     *identity.SignedKeyBundle
	SignedNetworkUpdate *identity.SignedNetworkUpdate
}

// Make a new session manager.
// Expects both address and privKeyBundle has been validated.
func NewSessionManager(privKeyBundle *identity.PrivateKeyBundle, currentNetAddress net.IP) (*SessionManager, error) {
	keybndl := privKeyBundle.Public()
	address, err := keybndl.Address()
	if err != nil {
		return nil, err
	}

	sigkeybndl, err := keybndl.Sign(privKeyBundle.SigningPrivateKey)
	if err != nil {
		return nil, err
	}

	netupd := &identity.NetworkUpdate{
		Timestamp:  common.Timestamp(time.Now().Unix()),
		NetAddress: currentNetAddress.To16(),
	}

	signetupd, err := netupd.Sign(privKeyBundle.SigningPrivateKey)
	if err != nil {
		return nil, err
	}

	return &SessionManager{
		sessions:            make(map[string]*Session),
		Address:             address,
		PrivateKeyBundle:    privKeyBundle,
		SignedKeyBundle:     sigkeybndl,
		SignedNetworkUpdate: signetupd,
	}, nil
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
