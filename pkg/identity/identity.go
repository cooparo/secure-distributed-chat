package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"net"
)

type IdentityAddress [20]byte

type KeyBundle struct {
	SigningKey *ed25519.PrivateKey
	DHKey      *ecdh.PrivateKey
	Signature  [64]byte
}

type NetAddrUpdate struct {
	Timestamp int64
	NetAddr   net.IP
}

type IdentityBundle struct {
	Address       IdentityAddress
	KeyBundle     KeyBundle
	NetAddrUpdate NetAddrUpdate
}
