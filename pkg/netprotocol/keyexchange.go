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
	SizeKeyExchangeRequest        = identity.SizeIdentityAddress*2 + identity.SizeSignedKeyBundle + identity.SizeSignedNetAddressUpdate + SizeEphemeralKey
	SizeSignedKeyExchangeRequest  = SizeKeyExchangeRequest + identity.SizeSignature
	SizeKeyExchangeResponse       = identity.SizeIdentityAddress*2 + SizeEphemeralKey + SizeRatchetKey
	SizeSignedKeyExchangeResponse = SizeKeyExchangeResponse + identity.SizeSignature
)

type KeyExchangeRequest struct {
	SendIDAddr             identity.IdentityAddress
	RecvIDAddr             identity.IdentityAddress
	SignedKeyBundle        *identity.SignedKeyBundle
	SignedNetAddressUpdate *identity.SignedNetAddressUpdate
	EphemeralKey           *ecdh.PublicKey
}

func (req *KeyExchangeRequest) AppendBinary(b []byte) ([]byte, error) {
	if err := req.SendIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if err := req.RecvIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if req.SignedKeyBundle == nil {
		return nil, &errs.IsNilError{SubjectName: "SignedKeyBundle"}
	}
	if req.SignedNetAddressUpdate == nil {
		return nil, &errs.IsNilError{SubjectName: "SignedNetAddressUpdate"}
	}
	if req.EphemeralKey == nil {
		return nil, &errs.IsNilError{SubjectName: "EphemeralKey"}
	}
	if req.EphemeralKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "EphemeralKey",
			SubjectActualCurve:   req.EphemeralKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}

	// Encode SendIDAddr
	b = append(b, req.SendIDAddr...)

	// Encode RecvIDAddr
	b = append(b, req.RecvIDAddr...)

	// Encode SignedKeyBundle
	b, err := req.SignedKeyBundle.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode SignedNetAddressUpdate
	b, err = req.SignedNetAddressUpdate.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode EphemeralKey
	b = append(b, req.EphemeralKey.Bytes()...)

	return b, nil
}

func (req *KeyExchangeRequest) MarshalBinary() ([]byte, error) {
	b, err := req.AppendBinary(make([]byte, 0, SizeKeyExchangeRequest))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (req *KeyExchangeRequest) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeKeyExchangeRequest {
		return &errs.SizeError{
			SubjectName:         "KeyExchangeRequest",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeKeyExchangeRequest,
		}
	}

	// Decode SendIDAddr
	req.SendIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(req.SendIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode RecvIDAddr
	req.RecvIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(req.RecvIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode SignedKeyBundle
	skbByte := make([]byte, identity.SizeSignedKeyBundle)
	copy(skbByte, buf[:identity.SizeSignedKeyBundle])
	var skb identity.SignedKeyBundle
	if err := skb.UnmarshalBinary(skbByte); err != nil {
		return err
	}
	req.SignedKeyBundle = &skb

	buf = buf[identity.SizeSignedKeyBundle:]

	// Decode SignedNetAddressUpdate
	snauByte := make([]byte, identity.SizeSignedNetAddressUpdate)
	copy(snauByte, buf[:identity.SizeSignedNetAddressUpdate])
	var snau identity.SignedNetAddressUpdate
	if err := snau.UnmarshalBinary(snauByte); err != nil {
		return err
	}
	req.SignedNetAddressUpdate = &snau

	buf = buf[identity.SizeSignedNetAddressUpdate:]

	// Decode EphemeralKey
	ekByte := make([]byte, SizeEphemeralKey)
	copy(ekByte, buf[:SizeEphemeralKey])
	curve := ecdh.X25519()
	ek, _ := curve.NewPublicKey(ekByte)
	req.EphemeralKey = ek

	return nil
}

func (req *KeyExchangeRequest) Sign(privateKey ed25519.PrivateKey) (*SignedKeyExchangeRequest, error) {
	data, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, data)

	sreq := SignedKeyExchangeRequest{
		Inner:     req,
		Signature: signature,
	}

	return &sreq, nil
}

type SignedKeyExchangeRequest struct {
	Inner     *KeyExchangeRequest
	Signature identity.Signature
}

func (sreq *SignedKeyExchangeRequest) AppendBinary(b []byte) ([]byte, error) {
	if err := sreq.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if sreq.Inner == nil {
		return nil, &errs.IsNilError{SubjectName: "Inner"}
	}

	// Encode Inner
	b, err := sreq.Inner.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Signature
	b = append(b, sreq.Signature...)

	return b, nil
}

func (sreq *SignedKeyExchangeRequest) MarshalBinary() ([]byte, error) {
	b, err := sreq.AppendBinary(make([]byte, 0, SizeSignedKeyExchangeRequest))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (sreq *SignedKeyExchangeRequest) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSignedKeyExchangeRequest {
		return &errs.SizeError{
			SubjectName:         "SignedKeyExchangeRequest",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSignedKeyExchangeRequest,
		}
	}

	// Decode Inner
	reqByte := make([]byte, SizeKeyExchangeRequest)
	copy(reqByte, buf[:SizeKeyExchangeRequest])
	var req KeyExchangeRequest
	if err := req.UnmarshalBinary(reqByte); err != nil {
		return err
	}
	sreq.Inner = &req

	buf = buf[SizeKeyExchangeRequest:]

	// Decode Signature
	sreq.Signature = make([]byte, identity.SizeSignature)
	copy(sreq.Signature, buf[:identity.SizeSignature])

	return nil
}

func (sreq *SignedKeyExchangeRequest) Verify(publicKey ed25519.PublicKey) error {
	if err := sreq.Signature.CheckSize(); err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyExchangeRequest"}, err)
	}

	data, err := sreq.Inner.MarshalBinary()
	if err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyExchangeRequest"}, err)
	}

	if !ed25519.Verify(publicKey, data, sreq.Signature) {
		return &identity.SignatureVerificationError{
			SubjectName: "SignedKeyExchangeRequest",
			SigningKey:  publicKey,
			Signature:   sreq.Signature,
		}
	}

	return nil
}

type KeyExchangeResponse struct {
	SendIDAddr   identity.IdentityAddress
	RecvIDAddr   identity.IdentityAddress
	EphemeralKey *ecdh.PublicKey
	RatchetKey   *ecdh.PublicKey
	Signature    identity.Signature
}

func (resp *KeyExchangeResponse) AppendBinary(b []byte) ([]byte, error) {
	if err := resp.SendIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if err := resp.RecvIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if resp.EphemeralKey == nil {
		return nil, &errs.IsNilError{SubjectName: "EphemeralKey"}
	}
	if resp.EphemeralKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "EphemeralKey",
			SubjectActualCurve:   resp.EphemeralKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}
	if resp.RatchetKey == nil {
		return nil, &errs.IsNilError{SubjectName: "RatchetKey"}
	}
	if resp.RatchetKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "RatchetKey",
			SubjectActualCurve:   resp.RatchetKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}
	if err := resp.Signature.CheckSize(); err != nil {
		return nil, err
	}

	// Encode SendIDAddr
	b = append(b, resp.SendIDAddr...)

	// Encode RecvIDAddr
	b = append(b, resp.RecvIDAddr...)

	// Encode EphemeralKey
	b = append(b, resp.EphemeralKey.Bytes()...)

	// Encode RatchetKey
	b = append(b, resp.RatchetKey.Bytes()...)

	// Encode Signature
	b = append(b, resp.Signature...)

	return b, nil
}

func (resp *KeyExchangeResponse) MarshalBinary() ([]byte, error) {
	b, err := resp.AppendBinary(make([]byte, 0, SizeKeyExchangeResponse))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (resp *KeyExchangeResponse) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeKeyExchangeResponse {
		return &errs.SizeError{
			SubjectName:         "KeyExchangeResponse",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeKeyExchangeResponse,
		}
	}

	// Decode SendIDAddr
	resp.SendIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(resp.SendIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode RecvIDAddr
	resp.RecvIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(resp.RecvIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode EphemeralKey
	ekByte := make([]byte, SizeEphemeralKey)
	copy(ekByte, buf[:SizeEphemeralKey])
	ekCurve := ecdh.X25519()
	ek, _ := ekCurve.NewPublicKey(ekByte)
	resp.EphemeralKey = ek

	buf = buf[SizeEphemeralKey:]

	// Decode RatchetKey
	rkByte := make([]byte, SizeRatchetKey)
	copy(rkByte, buf[:SizeRatchetKey])
	rkCurve := ecdh.X25519()
	rk, _ := rkCurve.NewPublicKey(rkByte)
	resp.RatchetKey = rk

	buf = buf[SizeRatchetKey:]

	// Decode Signature
	resp.Signature = make([]byte, identity.SizeSignature)
	copy(resp.Signature, buf[:identity.SizeSignature])

	return nil
}

func (resp *KeyExchangeResponse) Sign(privateKey ed25519.PrivateKey) (*SignedKeyExchangeResponse, error) {
	data, err := resp.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, data)

	sresp := SignedKeyExchangeResponse{
		Inner:     resp,
		Signature: signature,
	}

	return &sresp, nil
}

type SignedKeyExchangeResponse struct {
	Inner     *KeyExchangeResponse
	Signature identity.Signature
}

func (sresp *SignedKeyExchangeResponse) AppendBinary(b []byte) ([]byte, error) {
	if err := sresp.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if sresp.Inner == nil {
		return nil, &errs.IsNilError{SubjectName: "Inner"}
	}

	// Encode Inner
	b, err := sresp.Inner.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Signature
	b = append(b, sresp.Signature...)

	return b, nil
}

func (sresp *SignedKeyExchangeResponse) MarshalBinary() ([]byte, error) {
	b, err := sresp.AppendBinary(make([]byte, 0, SizeSignedKeyExchangeResponse))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (sresp *SignedKeyExchangeResponse) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSignedKeyExchangeResponse {
		return &errs.SizeError{
			SubjectName:         "SignedKeyExchangeResponse",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSignedKeyExchangeResponse,
		}
	}

	// Decode Inner
	respByte := make([]byte, SizeKeyExchangeResponse)
	copy(respByte, buf[:SizeKeyExchangeResponse])
	var resp KeyExchangeResponse
	if err := resp.UnmarshalBinary(respByte); err != nil {
		return err
	}
	sresp.Inner = &resp

	buf = buf[SizeKeyExchangeResponse:]

	// Decode Signature
	sresp.Signature = make([]byte, identity.SizeSignature)
	copy(sresp.Signature, buf[:identity.SizeSignature])

	return nil
}

func (sresp *SignedKeyExchangeResponse) Verify(publicKey ed25519.PublicKey) error {
	if err := sresp.Signature.CheckSize(); err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyExchangeResponse"}, err)
	}

	data, err := sresp.Inner.MarshalBinary()
	if err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedKeyExchangeResponse"}, err)
	}

	if !ed25519.Verify(publicKey, data, sresp.Signature) {
		return &identity.SignatureVerificationError{
			SubjectName: "SignedKeyExchangeResponse",
			SigningKey:  publicKey,
			Signature:   sresp.Signature,
		}
	}

	return nil
}
