package identity

import (
	"crypto/ed25519"
	"errors"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
)

const (
	SizeTimestamp           = 8
	SizeNetAddress          = 16
	SizeNetAddressUpdate    = SizeTimestamp + SizeNetAddress
	SizeSignedNetworkUpdate = SizeNetAddressUpdate + SizeSignature
)

type Timestamp int64

func (t *Timestamp) AppendBinary(b []byte) ([]byte, error) {
	ts := *t

	return append(b,
		byte(ts>>56),
		byte(ts>>48),
		byte(ts>>40),
		byte(ts>>32),
		byte(ts>>24),
		byte(ts>>16),
		byte(ts>>8),
		byte(ts)), nil
}

func (t *Timestamp) MarshalBinary() ([]byte, error) {
	b, err := t.AppendBinary(make([]byte, 0, SizeTimestamp))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (t *Timestamp) UnmarshalBinary(b []byte) error {
	ts := int64(b[7]) |
		int64(b[6])<<8 |
		int64(b[5])<<16 |
		int64(b[4])<<24 |
		int64(b[3])<<32 |
		int64(b[2])<<40 |
		int64(b[1])<<48 |
		int64(b[0])<<56

	*t = Timestamp(ts)
	return nil
}

type NetworkUpdate struct {
	Timestamp  Timestamp
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
	buf = buf[SizeTimestamp:]

	// Decode NetAddress
	copy(netupd.NetAddress, buf[:SizeNetAddressUpdate])

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
	var netupd NetworkUpdate
	if err := netupd.UnmarshalBinary(netupdByte); err != nil {
		return err
	}
	signetupd.Inner = &netupd

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
