package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/base64"
	"errors"
	"os"

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

func (privkeybndl *PrivateKeyBundle) AppendBinary(b []byte) ([]byte, error) {
	if privkeybndl.DiffieHellmanPrivateKey == nil {
		return nil, &errs.IsNilError{SubjectName: "DiffieHellmanPrivateKey"}
	}
	if privkeybndl.DiffieHellmanPrivateKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "DiffieHellmanPrivateKey",
			SubjectActualCurve:   privkeybndl.DiffieHellmanPrivateKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}

	if len(privkeybndl.SigningPrivateKey) != SizeSigningPrivateKey {
		return nil, &errs.SizeError{
			SubjectName:         "SigningPrivateKey",
			SubjectActualSize:   len(privkeybndl.SigningPrivateKey),
			SubjectExpectedSize: SizeSigningPrivateKey,
		}
	}

	// Encode SigningPrivateKey
	b = append(b, privkeybndl.SigningPrivateKey...)

	// Encode DiffieHellmanPrivateKey
	b = append(b, privkeybndl.DiffieHellmanPrivateKey.Bytes()...)

	return b, nil
}

func (privkeybndl *PrivateKeyBundle) MarshalBinary() ([]byte, error) {
	b, err := privkeybndl.AppendBinary(make([]byte, 0, SizePrivateKeyBundle))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (privkeybndl *PrivateKeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizePrivateKeyBundle {
		return &errs.SizeError{
			SubjectName:         "PrivateKeyBundle",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizePrivateKeyBundle,
		}
	}

	// Decode SigningPrivateKey
	privkeybndl.SigningPrivateKey = make([]byte, SizeSigningPrivateKey)
	copy(privkeybndl.SigningPrivateKey, buf[:SizeSigningPrivateKey])

	buf = buf[SizeSigningPrivateKey:]

	// Decode DiffieHellmanPrivateKey
	dhkeyBytes := make([]byte, SizeDiffieHellmanPrivateKey)
	copy(dhkeyBytes, buf[:SizeDiffieHellmanPrivateKey])
	curve := ecdh.X25519()
	dhkey, _ := curve.NewPrivateKey(dhkeyBytes)
	privkeybndl.DiffieHellmanPrivateKey = dhkey

	return nil
}

func (privkeybndl *PrivateKeyBundle) Save(fileName string) error {
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := privkeybndl.MarshalBinary()
	if err != nil {
		return err
	}

	encoding := base64.StdEncoding
	dst := make([]byte, encoding.EncodedLen(SizePrivateKeyBundle))
	encoding.Encode(dst, data)
	if _, err := f.Write(dst); err != nil {
		return err
	}

	return nil
}

func (privkeybndl *PrivateKeyBundle) Load(fileName string) error {
	f, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	encoding := base64.StdEncoding
	src := make([]byte, encoding.EncodedLen(SizePrivateKeyBundle))
	if _, err := f.Read(src); err != nil {
		return err
	}

	data := make([]byte, SizePrivateKeyBundle)
	if _, err := encoding.Decode(data, src); err != nil {
		return err
	}

	if err := privkeybndl.UnmarshalBinary(data); err != nil {
		return err
	}

	return nil

}

// Make KeyBundle
func (privkeybndl *PrivateKeyBundle) Public() *KeyBundle {
	return &KeyBundle{
		SigningKey:       privkeybndl.SigningPrivateKey.Public().(ed25519.PublicKey),
		DiffieHellmanKey: privkeybndl.DiffieHellmanPrivateKey.PublicKey(),
	}
}

type KeyBundle struct {
	SigningKey       ed25519.PublicKey
	DiffieHellmanKey *ecdh.PublicKey
}

func (keybndl *KeyBundle) AppendBinary(b []byte) ([]byte, error) {
	if keybndl.DiffieHellmanKey == nil {
		return nil, &errs.IsNilError{SubjectName: "DiffieHellmanKey"}
	}
	if keybndl.DiffieHellmanKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "DiffieHellmanKey",
			SubjectActualCurve:   keybndl.DiffieHellmanKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}

	if len(keybndl.SigningKey) != SizeSigningKey {
		return nil, &errs.SizeError{
			SubjectName:         "SigningKey",
			SubjectActualSize:   len(keybndl.SigningKey),
			SubjectExpectedSize: SizeSigningKey,
		}
	}

	// Encode SigningKey
	b = append(b, keybndl.SigningKey...)

	// Encode DiffieHellmanKey
	b = append(b, keybndl.DiffieHellmanKey.Bytes()...)

	return b, nil
}

func (keybndl *KeyBundle) MarshalBinary() ([]byte, error) {
	b, err := keybndl.AppendBinary(make([]byte, 0, SizeKeyBundle))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (keybndl *KeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeKeyBundle {
		return &errs.SizeError{
			SubjectName:         "KeyBundle",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeKeyBundle,
		}
	}

	// Decode SigningKey
	keybndl.SigningKey = make([]byte, SizeSigningKey)
	copy(keybndl.SigningKey, buf[:SizeSigningKey])

	buf = buf[SizeSigningKey:]

	// Decode DiffieHellmanKey
	dhkeyBytes := make([]byte, SizeDiffieHellmanKey)
	copy(dhkeyBytes, buf[:SizeDiffieHellmanKey])
	curve := ecdh.X25519()
	dhkey, _ := curve.NewPublicKey(dhkeyBytes)
	keybndl.DiffieHellmanKey = dhkey

	return nil
}

// Calculate the IdentityAddress from KeyBundle
func (keybndl *KeyBundle) Address() (IdentityAddress, error) {
	data, err := keybndl.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return sha3.SumSHAKE256(data, SizeIdentityAddress), nil
}

// Make a SignedKeyBundle
func (keybndl *KeyBundle) Sign(privateKey ed25519.PrivateKey) (*SignedKeyBundle, error) {
	data, err := keybndl.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, data)

	sigkeybndl := SignedKeyBundle{
		Inner:     keybndl,
		Signature: signature,
	}

	return &sigkeybndl, nil
}

type SignedKeyBundle struct {
	Inner     *KeyBundle
	Signature Signature
}

func (sigkeybndl *SignedKeyBundle) AppendBinary(b []byte) ([]byte, error) {
	if err := sigkeybndl.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if sigkeybndl.Inner == nil {
		return nil, &errs.IsNilError{SubjectName: "KeyBundle"}
	}

	// Encode Inner
	b, err := sigkeybndl.Inner.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Signature
	b = append(b, sigkeybndl.Signature...)

	return b, nil
}

func (sigkeybndl *SignedKeyBundle) MarshalBinary() ([]byte, error) {
	b, err := sigkeybndl.AppendBinary(make([]byte, 0, SizeSignedKeyBundle))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (sigkeybndl *SignedKeyBundle) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSignedKeyBundle {
		return &errs.SizeError{
			SubjectName:         "SignedKeyBundle",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSignedKeyBundle,
		}
	}

	// Decode Inner
	keybndlByte := make([]byte, SizeKeyBundle)
	copy(keybndlByte, buf[:SizeKeyBundle])
	keybndl := &KeyBundle{}
	if err := keybndl.UnmarshalBinary(keybndlByte); err != nil {
		return err
	}
	sigkeybndl.Inner = keybndl

	buf = buf[SizeKeyBundle:]

	// Decode Signature
	sigkeybndl.Signature = make([]byte, SizeSignature)
	copy(sigkeybndl.Signature, buf[:SizeSignature])

	return nil
}

// Verify the signed bundle
// Returns false if the internal Sizes are wrong
// and if the signature is invalid
func (sigkeybndl *SignedKeyBundle) Verify() error {
	if err := sigkeybndl.Signature.CheckSize(); err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyBundle"}, err)
	}

	data, err := sigkeybndl.Inner.MarshalBinary()
	if err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyBundle"}, err)
	}

	if !ed25519.Verify(sigkeybndl.Inner.SigningKey, data, sigkeybndl.Signature) {
		return &SignatureVerificationError{
			SubjectName: "Signed Key Bundle",
			SigningKey:  sigkeybndl.Inner.SigningKey,
			Signature:   sigkeybndl.Signature,
		}
	}

	return nil
}
