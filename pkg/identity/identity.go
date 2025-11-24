package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"io"
)

type IdentityAddress [20]byte

func (a IdentityAddress) String() string {
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	dst := make([]byte, encoding.EncodedLen(len(a)))
	encoding.Encode(dst, a[:])
	return string(dst)
}

func (a IdentityAddress) Equal(o IdentityAddress) bool {
	return bytes.Equal(a[:], o[:])
}

type KeyBundle struct {
	SigningKey ed25519.PublicKey
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

func (b *KeyBundle) Sign(privateKey ed25519.PrivateKey) error {
	var buffer bytes.Buffer
	err := b.Write(&buffer)
	if err != nil {
		return err
	}

	signature := ed25519.Sign(privateKey, buffer.Bytes()[:64])

	b.Signature = [64]byte(signature)

	return nil
}

func (b *KeyBundle) Verify(address IdentityAddress) (bool, error) {
	calcAddress, err := b.Address()
	if err != nil {
		return false, err
	}

	if !calcAddress.Equal(address) {
		return false, nil
	}

	var buffer bytes.Buffer
	err = b.Write(&buffer)
	if err != nil {
		return false, err
	}

	ok := ed25519.Verify(b.SigningKey, buffer.Bytes()[:64], b.Signature[:])
	if !ok {
		return false, nil
	}
	return true, nil
}

func (b *KeyBundle) Address() (IdentityAddress, error) {
	var buffer bytes.Buffer
	err := b.Write(&buffer)
	if err != nil {
		return IdentityAddress{}, err
	}

	h := sha256.New()
	_, err = h.Write(buffer.Bytes()[:64])
	if err != nil {
		return IdentityAddress{}, err
	}
	address := h.Sum(nil)[:20]

	return IdentityAddress(address), nil
}

type NetAddrUpdate struct {
	Timestamp int64
	NetAddr   [16]byte
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

	keySignature, err := signingKey.Sign(rand.Reader, pubKeys, nil)
	if err != nil {
		return [20]byte{}, nil, err
	}

	keyBundle := KeyBundle{
		SigningKey: pubSigningKey,
		DHKey:      dhKey.PublicKey(),
		Signature:  [64]byte(keySignature),
	}

	address, err := keyBundle.Address()
	if err != nil {
		return IdentityAddress{}, nil, err
	}

	// TODO: save privatekeys

	return address, &keyBundle, nil
}
