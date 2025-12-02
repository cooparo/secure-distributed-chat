package netprotocol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeEphemeralKey              = 32
	SizeKeyExchangeRequest        = identity.SizeIdentityAddress*2 + identity.SizeSignedKeyBundle + identity.SizeSignedNetworkUpdate + SizeEphemeralKey
	SizeSignedKeyExchangeRequest  = SizeKeyExchangeRequest + identity.SizeSignature
	SizeKeyExchangeResponse       = identity.SizeIdentityAddress*2 + SizeEphemeralKey + SizeRatchetKey
	SizeSignedKeyExchangeResponse = SizeKeyExchangeResponse + identity.SizeSignature
)

type KeyExchangeRequest struct {
	SendIDAddr          identity.IdentityAddress
	RecvIDAddr          identity.IdentityAddress
	SignedKeyBundle     *identity.SignedKeyBundle
	SignedNetworkUpdate *identity.SignedNetworkUpdate
	EphemeralKey        *ecdh.PublicKey
}

func (kexreq *KeyExchangeRequest) AppendBinary(b []byte) ([]byte, error) {
	if err := kexreq.SendIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if err := kexreq.RecvIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if kexreq.SignedKeyBundle == nil {
		return nil, &errs.IsNilError{SubjectName: "SignedKeyBundle"}
	}
	if kexreq.SignedNetworkUpdate == nil {
		return nil, &errs.IsNilError{SubjectName: "SignedNetAddressUpdate"}
	}
	if kexreq.EphemeralKey == nil {
		return nil, &errs.IsNilError{SubjectName: "EphemeralKey"}
	}
	if kexreq.EphemeralKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "EphemeralKey",
			SubjectActualCurve:   kexreq.EphemeralKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}

	// Encode SendIDAddr
	b = append(b, kexreq.SendIDAddr...)

	// Encode RecvIDAddr
	b = append(b, kexreq.RecvIDAddr...)

	// Encode SignedKeyBundle
	b, err := kexreq.SignedKeyBundle.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode SignedNetAddressUpdate
	b, err = kexreq.SignedNetworkUpdate.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode EphemeralKey
	b = append(b, kexreq.EphemeralKey.Bytes()...)

	return b, nil
}

func (kexreq *KeyExchangeRequest) MarshalBinary() ([]byte, error) {
	b, err := kexreq.AppendBinary(make([]byte, 0, SizeKeyExchangeRequest))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (kexreq *KeyExchangeRequest) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeKeyExchangeRequest {
		return &errs.SizeError{
			SubjectName:         "KeyExchangeRequest",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeKeyExchangeRequest,
		}
	}

	// Decode SendIDAddr
	kexreq.SendIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(kexreq.SendIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode RecvIDAddr
	kexreq.RecvIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(kexreq.RecvIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode SignedKeyBundle
	sigkeybndlByte := make([]byte, identity.SizeSignedKeyBundle)
	copy(sigkeybndlByte, buf[:identity.SizeSignedKeyBundle])
	sigkeybndl := &identity.SignedKeyBundle{}
	if err := sigkeybndl.UnmarshalBinary(sigkeybndlByte); err != nil {
		return err
	}
	kexreq.SignedKeyBundle = sigkeybndl

	buf = buf[identity.SizeSignedKeyBundle:]

	// Decode SignedNetAddressUpdate
	signetupdByte := make([]byte, identity.SizeSignedNetworkUpdate)
	copy(signetupdByte, buf[:identity.SizeSignedNetworkUpdate])
	signetupd := &identity.SignedNetworkUpdate{}
	if err := signetupd.UnmarshalBinary(signetupdByte); err != nil {
		return err
	}
	kexreq.SignedNetworkUpdate = signetupd

	buf = buf[identity.SizeSignedNetworkUpdate:]

	// Decode EphemeralKey
	ekeyByte := make([]byte, SizeEphemeralKey)
	copy(ekeyByte, buf[:SizeEphemeralKey])
	curve := ecdh.X25519()
	ekey, _ := curve.NewPublicKey(ekeyByte)
	kexreq.EphemeralKey = ekey

	return nil
}

func (kexreq *KeyExchangeRequest) Sign(privateKey ed25519.PrivateKey) (*SignedKeyExchangeRequest, error) {
	data, err := kexreq.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, data)

	sigkexreq := SignedKeyExchangeRequest{
		Inner:     kexreq,
		Signature: signature,
	}

	return &sigkexreq, nil
}

type SignedKeyExchangeRequest struct {
	Inner     *KeyExchangeRequest
	Signature identity.Signature
}

func (sigkexreq *SignedKeyExchangeRequest) AppendBinary(b []byte) ([]byte, error) {
	if err := sigkexreq.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if sigkexreq.Inner == nil {
		return nil, &errs.IsNilError{SubjectName: "Inner"}
	}

	// Encode Inner
	b, err := sigkexreq.Inner.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Signature
	b = append(b, sigkexreq.Signature...)

	return b, nil
}

func (sigkexreq *SignedKeyExchangeRequest) MarshalBinary() ([]byte, error) {
	b, err := sigkexreq.AppendBinary(make([]byte, 0, SizeSignedKeyExchangeRequest))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (sigkexreq *SignedKeyExchangeRequest) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSignedKeyExchangeRequest {
		return &errs.SizeError{
			SubjectName:         "SignedKeyExchangeRequest",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSignedKeyExchangeRequest,
		}
	}

	// Decode Inner
	kexreqByte := make([]byte, SizeKeyExchangeRequest)
	copy(kexreqByte, buf[:SizeKeyExchangeRequest])
	kexreq := &KeyExchangeRequest{}
	if err := kexreq.UnmarshalBinary(kexreqByte); err != nil {
		return err
	}
	sigkexreq.Inner = kexreq

	buf = buf[SizeKeyExchangeRequest:]

	// Decode Signature
	sigkexreq.Signature = make([]byte, identity.SizeSignature)
	copy(sigkexreq.Signature, buf[:identity.SizeSignature])

	return nil
}

func (sigkexreq *SignedKeyExchangeRequest) Verify(publicKey ed25519.PublicKey) error {
	if err := sigkexreq.Signature.CheckSize(); err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyExchangeRequest"}, err)
	}

	data, err := sigkexreq.Inner.MarshalBinary()
	if err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyExchangeRequest"}, err)
	}

	if !ed25519.Verify(publicKey, data, sigkexreq.Signature) {
		return &identity.SignatureVerificationError{
			SubjectName: "SignedKeyExchangeRequest",
			SigningKey:  publicKey,
			Signature:   sigkexreq.Signature,
		}
	}

	return nil
}

type KeyExchangeResponse struct {
	SendIDAddr   identity.IdentityAddress
	RecvIDAddr   identity.IdentityAddress
	EphemeralKey *ecdh.PublicKey
	RatchetKey   *ecdh.PublicKey
}

func (kexresp *KeyExchangeResponse) AppendBinary(b []byte) ([]byte, error) {
	if err := kexresp.SendIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if err := kexresp.RecvIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if kexresp.EphemeralKey == nil {
		return nil, &errs.IsNilError{SubjectName: "EphemeralKey"}
	}
	if kexresp.EphemeralKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "EphemeralKey",
			SubjectActualCurve:   kexresp.EphemeralKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}
	if kexresp.RatchetKey == nil {
		return nil, &errs.IsNilError{SubjectName: "RatchetKey"}
	}
	if kexresp.RatchetKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "RatchetKey",
			SubjectActualCurve:   kexresp.RatchetKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}

	// Encode SendIDAddr
	b = append(b, kexresp.SendIDAddr...)

	// Encode RecvIDAddr
	b = append(b, kexresp.RecvIDAddr...)

	// Encode EphemeralKey
	b = append(b, kexresp.EphemeralKey.Bytes()...)

	// Encode RatchetKey
	b = append(b, kexresp.RatchetKey.Bytes()...)

	return b, nil
}

func (kexresp *KeyExchangeResponse) MarshalBinary() ([]byte, error) {
	b, err := kexresp.AppendBinary(make([]byte, 0, SizeKeyExchangeResponse))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (kexresp *KeyExchangeResponse) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeKeyExchangeResponse {
		return &errs.SizeError{
			SubjectName:         "KeyExchangeResponse",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeKeyExchangeResponse,
		}
	}

	// Decode SendIDAddr
	kexresp.SendIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(kexresp.SendIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode RecvIDAddr
	kexresp.RecvIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(kexresp.RecvIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode EphemeralKey
	ekeyByte := make([]byte, SizeEphemeralKey)
	copy(ekeyByte, buf[:SizeEphemeralKey])
	ekeyCurve := ecdh.X25519()
	ekey, _ := ekeyCurve.NewPublicKey(ekeyByte)
	kexresp.EphemeralKey = ekey

	buf = buf[SizeEphemeralKey:]

	// Decode RatchetKey
	rkeyByte := make([]byte, SizeRatchetKey)
	copy(rkeyByte, buf[:SizeRatchetKey])
	rkeyCurve := ecdh.X25519()
	rkey, _ := rkeyCurve.NewPublicKey(rkeyByte)
	kexresp.RatchetKey = rkey

	buf = buf[SizeRatchetKey:]

	return nil
}

func (kexresp *KeyExchangeResponse) Sign(privateKey ed25519.PrivateKey) (*SignedKeyExchangeResponse, error) {
	data, err := kexresp.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, data)

	sigkexresp := SignedKeyExchangeResponse{
		Inner:     kexresp,
		Signature: signature,
	}

	return &sigkexresp, nil
}

type SignedKeyExchangeResponse struct {
	Inner     *KeyExchangeResponse
	Signature identity.Signature
}

func (sigkexresp *SignedKeyExchangeResponse) AppendBinary(b []byte) ([]byte, error) {
	if err := sigkexresp.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if sigkexresp.Inner == nil {
		return nil, &errs.IsNilError{SubjectName: "Inner"}
	}

	// Encode Inner
	b, err := sigkexresp.Inner.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Signature
	b = append(b, sigkexresp.Signature...)

	return b, nil
}

func (sigkexresp *SignedKeyExchangeResponse) MarshalBinary() ([]byte, error) {
	b, err := sigkexresp.AppendBinary(make([]byte, 0, SizeSignedKeyExchangeResponse))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (sigkexresp *SignedKeyExchangeResponse) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSignedKeyExchangeResponse {
		return &errs.SizeError{
			SubjectName:         "SignedKeyExchangeResponse",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSignedKeyExchangeResponse,
		}
	}

	// Decode Inner
	kexrespByte := make([]byte, SizeKeyExchangeResponse)
	copy(kexrespByte, buf[:SizeKeyExchangeResponse])
	kexresp := &KeyExchangeResponse{}
	if err := kexresp.UnmarshalBinary(kexrespByte); err != nil {
		return err
	}
	sigkexresp.Inner = kexresp

	buf = buf[SizeKeyExchangeResponse:]

	// Decode Signature
	sigkexresp.Signature = make([]byte, identity.SizeSignature)
	copy(sigkexresp.Signature, buf[:identity.SizeSignature])

	return nil
}

func (sigkexresp *SignedKeyExchangeResponse) Verify(publicKey ed25519.PublicKey) error {
	if err := sigkexresp.Signature.CheckSize(); err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyExchangeResponse"}, err)
	}

	data, err := sigkexresp.Inner.MarshalBinary()
	if err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyExchangeResponse"}, err)
	}

	if !ed25519.Verify(publicKey, data, sigkexresp.Signature) {
		return &identity.SignatureVerificationError{
			SubjectName: "SignedKeyExchangeResponse",
			SigningKey:  publicKey,
			Signature:   sigkexresp.Signature,
		}
	}

	return nil
}
