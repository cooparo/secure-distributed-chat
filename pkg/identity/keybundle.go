package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha3"
	"errors"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
)

const (
	SizeSigningPrivateKey       = 64
	SizeDiffieHellmanPrivateKey = 32
	SizePrivateKeyBundle        = SizeSigningPrivateKey + SizeDiffieHellmanPrivateKey
	SizeSigningKey              = 32
	SizeDiffieHellmanKey        = 32
	SizeKeyBundle               = SizeSigningKey + SizeDiffieHellmanKey
	SizeSignedKeyBundle         = SizeKeyBundle + SizeSignature
)

type PrivateKeyBundle struct {
	SigningPrivateKey       ed25519.PrivateKey
	DiffieHellmanPrivateKey *ecdh.PrivateKey
}

func (pkb *PrivateKeyBundle) AppendBinary(b []byte) ([]byte, error) {
	if pkb.DiffieHellmanPrivateKey == nil {
		return nil, &errs.IsNilError{SubjectName: "DiffieHellmanPrivateKey"}
	}
	if pkb.DiffieHellmanPrivateKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "DiffieHellmanPrivateKey",
			SubjectActualCurve:   pkb.DiffieHellmanPrivateKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}

	if len(pkb.SigningPrivateKey) != SizeSigningPrivateKey {
		return nil, &errs.SizeError{
			SubjectName:         "SigningPrivateKey",
			SubjectActualSize:   len(pkb.SigningPrivateKey),
			SubjectExpectedSize: SizeSigningPrivateKey,
		}
	}

	// Encode SigningPrivateKey
	b = append(b, pkb.SigningPrivateKey...)

	// Encode DiffieHellmanPrivateKey
	b = append(b, pkb.DiffieHellmanPrivateKey.Bytes()...)

	return b, nil
}

func (pkb *PrivateKeyBundle) MarshalBinary() ([]byte, error) {
	b, err := pkb.AppendBinary(make([]byte, 0, SizePrivateKeyBundle))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (pkb *PrivateKeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizePrivateKeyBundle {
		return &errs.SizeError{
			SubjectName:         "PrivateKeyBundle",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizePrivateKeyBundle,
		}
	}

	// Decode SigningPrivateKey
	pkb.SigningPrivateKey = make([]byte, SizeSigningPrivateKey)
	copy(pkb.SigningPrivateKey, buf[:SizeSigningPrivateKey])

	buf = buf[SizeSigningPrivateKey:]

	// Decode DiffieHellmanPrivateKey
	dhpkBytes := make([]byte, SizeDiffieHellmanPrivateKey)
	copy(dhpkBytes, buf[:SizeDiffieHellmanPrivateKey])
	curve := ecdh.X25519()
	dhpk, _ := curve.NewPrivateKey(dhpkBytes)
	pkb.DiffieHellmanPrivateKey = dhpk

	return nil
}

// Make KeyBundle
func (pkb *PrivateKeyBundle) Public() *KeyBundle {
	return &KeyBundle{
		SigningKey:       pkb.SigningPrivateKey.Public().(ed25519.PublicKey),
		DiffieHellmanKey: pkb.DiffieHellmanPrivateKey.PublicKey(),
	}
}

type KeyBundle struct {
	SigningKey       ed25519.PublicKey
	DiffieHellmanKey *ecdh.PublicKey
}

func (kb *KeyBundle) AppendBinary(b []byte) ([]byte, error) {
	if kb.DiffieHellmanKey == nil {
		return nil, &errs.IsNilError{SubjectName: "DiffieHellmanKey"}
	}
	if kb.DiffieHellmanKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "DiffieHellmanKey",
			SubjectActualCurve:   kb.DiffieHellmanKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}

	if len(kb.SigningKey) != SizeSigningKey {
		return nil, &errs.SizeError{
			SubjectName:         "SigningKey",
			SubjectActualSize:   len(kb.SigningKey),
			SubjectExpectedSize: SizeSigningKey,
		}
	}

	// Encode SigningKey
	b = append(b, kb.SigningKey...)

	// Encode DiffieHellmanKey
	b = append(b, kb.DiffieHellmanKey.Bytes()...)

	return b, nil
}

func (kb *KeyBundle) MarshalBinary() ([]byte, error) {
	b, err := kb.AppendBinary(make([]byte, 0, SizeKeyBundle))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (kb *KeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeKeyBundle {
		return &errs.SizeError{
			SubjectName:         "KeyBundle",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeKeyBundle,
		}
	}

	// Decode SigningKey
	kb.SigningKey = make([]byte, SizeSigningKey)
	copy(kb.SigningKey, buf[:SizeSigningKey])

	buf = buf[SizeSigningKey:]

	// Decode DiffieHellmanKey
	dhkBytes := make([]byte, SizeDiffieHellmanKey)
	copy(dhkBytes, buf[:SizeDiffieHellmanKey])
	curve := ecdh.X25519()
	dhk, _ := curve.NewPublicKey(dhkBytes)
	kb.DiffieHellmanKey = dhk

	return nil
}

// Calculate the IdentityAddress from KeyBundle
func (kb *KeyBundle) Address() (IdentityAddress, error) {
	data, err := kb.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return sha3.SumSHAKE256(data, SizeIdentityAddress), nil
}

// Make a SignedKeyBundle
func (kb *KeyBundle) Sign(privateKey ed25519.PrivateKey) (*SignedKeyBundle, error) {
	data, err := kb.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, data)

	skb := SignedKeyBundle{
		KeyBundle: kb,
		Signature: signature,
	}

	return &skb, nil
}

type SignedKeyBundle struct {
	KeyBundle *KeyBundle
	Signature Signature
}

func (skb *SignedKeyBundle) AppendBinary(b []byte) ([]byte, error) {
	if err := skb.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if skb.KeyBundle == nil {
		return nil, &errs.IsNilError{SubjectName: "KeyBundle"}
	}

	// Encode KeyBundle
	b, err := skb.KeyBundle.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Signature
	b = append(b, skb.Signature...)

	return b, nil
}

func (skb *SignedKeyBundle) MarshalBinary() ([]byte, error) {
	b, err := skb.AppendBinary(make([]byte, 0, SizeSignedKeyBundle))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (skb *SignedKeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSignedKeyBundle {
		return &errs.SizeError{
			SubjectName:         "SignedKeyBundle",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSignedKeyBundle,
		}
	}

	// Decode KeyBundle
	kbByte := make([]byte, SizeKeyBundle)
	copy(kbByte, buf[:SizeKeyBundle])
	var kb KeyBundle
	if err := kb.UnmarshalBinary(kbByte); err != nil {
		return err
	}
	skb.KeyBundle = &kb

	buf = buf[SizeKeyBundle:]

	// Decode Signature
	skb.Signature = make([]byte, SizeSignature)
	copy(skb.Signature, buf[:SizeSignature])

	return nil
}

// Verify the signed bundle
// Returns false if the internal Sizes are wrong
// and if the signature is invalid
func (skb *SignedKeyBundle) Verify() error {
	if err := skb.Signature.CheckSize(); err != nil {
		return errors.Join(&VerificationError{SubjectName: "SignedKeyBundle"}, err)
	}

	data, err := skb.KeyBundle.MarshalBinary()
	if err != nil {
		return errors.Join(&VerificationError{SubjectName: "SignedKeyBundle"}, err)
	}

	if !ed25519.Verify(skb.KeyBundle.SigningKey, data, skb.Signature) {
		return &SignatureVerificationError{
			SubjectName: "SignedKeyBundle",
			SigningKey:  skb.KeyBundle.SigningKey,
			Signature:   skb.Signature,
		}
	}

	return nil
}
