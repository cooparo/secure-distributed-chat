package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	Signature [64]byte
}

func GenerateIdentity() (IdentityAddress, *KeyBundle, error) {
	pubSigningKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return [20]byte{}, nil, err
	}
	dhKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return [20]byte{}, nil, err
	}

	pubKeys := append(pubSigningKey, dhKey.PublicKey().Bytes()...)

	h := sha256.New()
	h.Write(pubKeys)
	address := h.Sum(nil)[:20]

	keySignature, err := signingKey.Sign(rand.Reader, pubKeys, nil)
	if err != nil {
		return [20]byte{}, nil, err
	}

	keyBundle := KeyBundle{
		SigningKey: &signingKey,
		DHKey:      dhKey,
		Signature:  [64]byte(keySignature),
	}

	return [20]byte(address), &keyBundle, nil
}

func (k *KeyBundle) Public() []byte {
	pubBundle := append(k.SigningKey.Public().([]byte), k.DHKey.PublicKey().Bytes()...)
	pubBundle = append(pubBundle, k.Signature[:]...)
	return pubBundle
}
