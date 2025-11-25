package session

import (
	"crypto/ecdh"

	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

type Session struct {
	Ratchet              *doubleratchet.DoubleRatchet
	KeyBundle            *identity.KeyBundle
	EphemeralExchangeKey *ecdh.PrivateKey
}
