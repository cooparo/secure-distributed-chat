package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
)

type IdentityAddress [20]byte

type KeyBundle struct {
	SigningKey *ed25519.PublicKey
	DHKey      *ecdh.PublicKey
	Signature  [64]byte
}

func (b *KeyBundle) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, b.SigningKey)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, b.DHKey.Bytes())
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.BigEndian, b.Signature)
	if err != nil {
		return err
	}

	return nil
}

func ReadKeyBundle(r io.Reader) (*KeyBundle, error) {
	b := KeyBundle{}
	err := binary.Read(r, binary.BigEndian, &b.SigningKey)
	if err != nil {
		return nil, err
	}

	dhKeyBytes := make([]byte, 32)
	err = binary.Read(r, binary.BigEndian, dhKeyBytes)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.BigEndian, b.Signature)
	if err != nil {
		return nil, err
	}

	dhKey, err := ecdh.X25519().NewPublicKey(dhKeyBytes)
	if err != nil {
		return nil, err
	}
	b.DHKey = dhKey

	return &b, nil
}

type NetAddrUpdate struct {
	Timestamp int64
	NetAddr   net.IP
	Signature [64]byte
}

func (n *NetAddrUpdate) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, n)
	if err != nil {
		return err
	}

	return nil
}

func ReadNetAddrUpdate(r io.Reader) (*NetAddrUpdate, error) {
	n := NetAddrUpdate{}
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		return nil, err
	}

	return &n, nil
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
		SigningKey: &pubSigningKey,
		DHKey:      dhKey.PublicKey(),
		Signature:  [64]byte(keySignature),
	}

	// TODO: save privatekeys

	return [20]byte(address), &keyBundle, nil
}
