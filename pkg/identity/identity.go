package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
)

const (
	SizeIdentityAddress = 20
	SizeSignature       = 64
)

type IdentityAddress []byte

func (a IdentityAddress) Base32() string {
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	dst := make([]byte, encoding.EncodedLen(len(a)))
	encoding.Encode(dst, a)
	return string(dst)
}

func IdentityFromBase32(s string) (IdentityAddress, error) {
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	dst := make([]byte, encoding.DecodedLen(len(s)))
	if _, err := encoding.Decode(dst, []byte(s)); err != nil {
		return nil, err
	}

	return IdentityAddress(dst), nil
}

func (a IdentityAddress) Equal(o IdentityAddress) bool {
	return bytes.Equal(a, o)
}

func (a IdentityAddress) CheckSize() error {
	if len(a) != SizeIdentityAddress {
		return &errs.SizeError{
			SubjectName:         "IdentityAddress",
			SubjectActualSize:   len(a),
			SubjectExpectedSize: SizeIdentityAddress,
		}
	}
	return nil
}

type Signature []byte

func (s Signature) CheckSize() error {
	if len(s) != SizeSignature {
		return &errs.SizeError{
			SubjectName:         "Signature",
			SubjectActualSize:   len(s),
			SubjectExpectedSize: SizeSignature,
		}
	}
	return nil
}

func GenerateIdentity() (*PrivateKeyBundle, error) {
	_, privSign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	privdh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	privkeybndl := PrivateKeyBundle{
		SigningPrivateKey:       privSign,
		DiffieHellmanPrivateKey: privdh,
	}

	return &privkeybndl, nil
}
