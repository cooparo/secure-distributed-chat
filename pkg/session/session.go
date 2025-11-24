package session

import (
	"crypto/ecdh"
	"crypto/ed25519"

	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
)

type Session struct {
	Ratchet     *doubleratchet.DoubleRatchet
	SigningKey  ed25519.PublicKey
	ExchangeKey *ecdh.PrivateKey
}
