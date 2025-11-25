package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha3"
)

const (
	SigningPrivateKeySize       = 64
	DiffieHellmanPrivateKeySize = 32
	PrivateKeyBundleSize        = SigningPrivateKeySize + DiffieHellmanPrivateKeySize
	SigningKeySize              = 32
	DiffieHellmanKeySize        = 32
	KeyBundleSize               = SigningKeySize + DiffieHellmanKeySize
	SignedKeyBundleSize         = KeyBundleSize + SignatureSize
)

type PrivateKeyBundle struct {
	SigningPrivateKey       ed25519.PrivateKey
	DiffieHellmanPrivateKey *ecdh.PrivateKey
}

func (pkb *PrivateKeyBundle) AppendBinary(b []byte) ([]byte, error) {
	if pkb.DiffieHellmanPrivateKey == nil {
		return nil, &ErrIsNil{SubjectName: "DiffieHellmanPrivateKey"}
	}
	if pkb.DiffieHellmanPrivateKey.Curve() != ecdh.X25519() {
		return nil, &ErrInvalidCurve{Curve: pkb.DiffieHellmanPrivateKey.Curve()}
	}

	if len(pkb.SigningPrivateKey) != SigningPrivateKeySize {
		return nil, &ErrInvalidSize{
			SubjectName: "SigningPrivateKey",
			SubjectSize: len(pkb.SigningPrivateKey),
		}
	}

	dhkByte := pkb.DiffieHellmanPrivateKey.Bytes()
	if len(dhkByte) != DiffieHellmanPrivateKeySize {
		return nil, &ErrInvalidSize{
			SubjectName: "DiffieHellmanPrivateKey",
			SubjectSize: len(dhkByte),
		}
	}

	// Encode SigningPrivateKey
	b = append(b, pkb.SigningPrivateKey...)

	// Encode DiffieHellmanPrivateKey
	b = append(b, dhkByte...)

	return b, nil
}

func (pkb *PrivateKeyBundle) MarshalBinary() ([]byte, error) {
	b, err := pkb.AppendBinary(make([]byte, PrivateKeyBundleSize))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (pkb *PrivateKeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != PrivateKeyBundleSize {
		return &ErrInvalidSize{
			SubjectName: "PrivateKeyBundle",
			SubjectSize: len(buf),
		}
	}

	// Decode SigningPrivateKey
	pkb.SigningPrivateKey = make([]byte, SigningPrivateKeySize)
	copy(pkb.SigningPrivateKey, buf[:SigningPrivateKeySize])

	buf = buf[SigningPrivateKeySize:]

	// Decode DiffieHellmanPrivateKey
	dhpkBytes := make([]byte, DiffieHellmanPrivateKeySize)
	copy(dhpkBytes, buf[:DiffieHellmanPrivateKeySize])
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
		return nil, &ErrIsNil{SubjectName: "DiffieHellmanKey"}
	}
	if kb.DiffieHellmanKey.Curve() != ecdh.X25519() {
		return nil, &ErrInvalidCurve{Curve: kb.DiffieHellmanKey.Curve()}
	}

	if len(kb.SigningKey) != SigningKeySize {
		return nil, &ErrInvalidSize{
			SubjectName: "SigningKey",
			SubjectSize: len(kb.SigningKey),
		}
	}

	dhkByte := kb.DiffieHellmanKey.Bytes()
	if len(dhkByte) != DiffieHellmanKeySize {
		return nil, &ErrInvalidSize{
			SubjectName: "DiffieHellmanKey",
			SubjectSize: len(dhkByte),
		}
	}

	// Encode SigningKey
	b = append(b, kb.SigningKey...)

	// Encode DiffieHellmanKey
	b = append(b, dhkByte...)

	return b, nil
}

func (kb *KeyBundle) MarshalBinary() ([]byte, error) {
	b, err := kb.AppendBinary(make([]byte, KeyBundleSize))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (kb *KeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != KeyBundleSize {
		return &ErrInvalidSize{
			SubjectName: "KeyBundle",
			SubjectSize: len(buf),
		}
	}

	// Decode SigningKey
	kb.SigningKey = make([]byte, SigningKeySize)
	copy(kb.SigningKey, buf[:SigningKeySize])

	buf = buf[SigningKeySize:]

	// Decode DiffieHellmanKey
	dhkBytes := make([]byte, DiffieHellmanKeySize)
	copy(dhkBytes, buf[:DiffieHellmanKeySize])
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

	return sha3.SumSHAKE256(data, IdentityAddressSize), nil
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
	Signature []byte
}

func (skb *SignedKeyBundle) AppendBinary(b []byte) ([]byte, error) {
	if len(skb.Signature) != SignatureSize {
		return nil, &ErrInvalidSize{
			SubjectName: "Signature",
			SubjectSize: len(skb.Signature),
		}
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
	b, err := skb.AppendBinary(make([]byte, SignedKeyBundleSize))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (skb *SignedKeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SignedKeyBundleSize {
		return &ErrInvalidSize{
			SubjectName: "SignedKeyBundle",
			SubjectSize: len(buf),
		}
	}

	// Decode KeyBundle
	kbByte := make([]byte, KeyBundleSize)
	copy(kbByte, buf[:KeyBundleSize])
	var kb KeyBundle
	kb.UnmarshalBinary(kbByte)
	skb.KeyBundle = &kb

	buf = buf[KeyBundleSize:]

	// Decode Signature
	skb.Signature = make([]byte, SignatureSize)
	copy(skb.Signature, buf[:SignatureSize])

	return nil
}

// Verify the signed bundle
// Returns false if the internal Sizes are wrong
// and if the signature is invalid
func (skb *SignedKeyBundle) Verify() bool {
	if len(skb.Signature) != SignatureSize {
		return false
	}

	data, err := skb.KeyBundle.MarshalBinary()
	if err != nil {
		return false
	}

	return ed25519.Verify(skb.KeyBundle.SigningKey, data, skb.Signature)
}
