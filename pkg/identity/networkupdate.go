package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
)

const (
	SizeNetAddress          = 16
	SizeNetAddressUpdate    = common.SizeTimestamp + SizeNetAddress
	SizeSignedNetworkUpdate = SizeNetAddressUpdate + SizeSignature
)

type NetworkUpdate struct {
	Timestamp  common.Timestamp
	NetAddress net.IP
}

func (netupd *NetworkUpdate) AppendBinary(b []byte) ([]byte, error) {
	if len(netupd.NetAddress) != SizeNetAddress {
		return nil, &errs.SizeError{
			SubjectName:         "NetAddress",
			SubjectActualSize:   len(netupd.NetAddress),
			SubjectExpectedSize: SizeNetAddress,
		}
	}

	// Encode Timestamp
	b, err := netupd.Timestamp.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode NetAddress
	b = append(b, netupd.NetAddress...)

	return b, nil
}

func (netupd *NetworkUpdate) MarshalBinary() ([]byte, error) {
	b, err := netupd.AppendBinary(make([]byte, 0, SizeNetAddressUpdate))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (netupd *NetworkUpdate) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeNetAddressUpdate {
		return &errs.SizeError{
			SubjectName:         "NetAddressUpdate",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeNetAddressUpdate,
		}
	}

	// Decode Timestamp
	if err := netupd.Timestamp.UnmarshalBinary(buf); err != nil {
		return err
	}
	buf = buf[common.SizeTimestamp:]

	// Decode NetAddress
	netupd.NetAddress = make(net.IP, SizeNetAddress)
	copy(netupd.NetAddress, buf[:SizeNetAddress])

	return nil
}

// Make a SignedNetworkUpdate
func (netupd *NetworkUpdate) Sign(privateKey ed25519.PrivateKey) (*SignedNetworkUpdate, error) {
	data, err := netupd.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, data)

	signetupd := SignedNetworkUpdate{
		Inner:     netupd,
		Signature: signature,
	}

	return &signetupd, nil
}

type SignedNetworkUpdate struct {
	Inner     *NetworkUpdate
	Signature Signature
}

func (signetupd *SignedNetworkUpdate) AppendBinary(b []byte) ([]byte, error) {
	if err := signetupd.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if signetupd.Inner == nil {
		return nil, &errs.IsNilError{SubjectName: "NetAddressUpdate"}
	}

	// Encode Inner
	b, err := signetupd.Inner.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Signature
	b = append(b, signetupd.Signature...)

	return b, nil
}

func (signetupd *SignedNetworkUpdate) MarshalBinary() ([]byte, error) {
	b, err := signetupd.AppendBinary(make([]byte, 0, SizeSignedNetworkUpdate))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (signetupd *SignedNetworkUpdate) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSignedNetworkUpdate {
		return &errs.SizeError{
			SubjectName:         "SignedNetAddressUpdate",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSignedNetworkUpdate,
		}
	}

	// Decode Inner
	netupdByte := make([]byte, SizeNetAddressUpdate)
	copy(netupdByte, buf[:SizeNetAddressUpdate])
	netupd := &NetworkUpdate{}
	if err := netupd.UnmarshalBinary(netupdByte); err != nil {
		return err
	}
	signetupd.Inner = netupd

	buf = buf[SizeNetAddressUpdate:]

	// Decode Signature
	signetupd.Signature = make([]byte, SizeSignature)
	copy(signetupd.Signature, buf[:SizeSignature])

	return nil
}

func (signetupd *SignedNetworkUpdate) Verify(publicKey ed25519.PublicKey) error {
	if err := signetupd.Signature.CheckSize(); err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedNetAddressUpdate"}, err)
	}

	data, err := signetupd.Inner.MarshalBinary()
	if err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedNetAddressUpdate"}, err)
	}

	if !ed25519.Verify(publicKey, data, signetupd.Signature) {
		return &SignatureVerificationError{
			SubjectName: "SignedNetAddress",
			SigningKey:  publicKey,
			Signature:   signetupd.Signature,
		}
	}

	return nil
}

// Base64 Encode the signed update
func (signetupd *SignedNetworkUpdate) Encode() (string, error) {
	signetupdByte, err := signetupd.MarshalBinary()
	if err != nil {
		return "", err
	}

	encoding := base64.StdEncoding
	dst := make([]byte, encoding.EncodedLen(len(signetupdByte)))
	encoding.Encode(dst, signetupdByte)
	return string(dst), nil
}

// Base64 Decode the signed update
func (signetupd *SignedNetworkUpdate) Decode(s string) error {
	encoding := base64.StdEncoding
	dst := make([]byte, encoding.DecodedLen(len(s)))
	n, err := encoding.Decode(dst, []byte(s))
	if err != nil {
		return err
	}

	if err := signetupd.UnmarshalBinary(dst[:n]); err != nil {
		return err
	}

	return nil
}
