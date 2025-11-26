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
	encoding.Encode(dst, a[:])
	return string(dst)
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

func GenerateIdentity() (IdentityAddress, *SignedKeyBundle, error) {
	_, privSign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privdh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pkb := PrivateKeyBundle{
		SigningPrivateKey:       privSign,
		DiffieHellmanPrivateKey: privdh,
	}

	kb := pkb.Public()

	skb, err := kb.Sign(privSign)

	address, err := kb.Address()
	if err != nil {
		return nil, nil, err
	}

	// TODO: save privatekeys

	return address, skb, nil
}
