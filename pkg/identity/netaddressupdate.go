package identity

import (
	"crypto/ed25519"
	"errors"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
)

const (
	SizeTimestamp              = 8
	SizeNetAddress             = 16
	SizeNetAddressUpdate       = SizeTimestamp + SizeNetAddress
	SizeSignedNetAddressUpdate = SizeNetAddressUpdate + SizeSignature
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
	return t.AppendBinary(make([]byte, 0, SizeTimestamp))
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

type NetAddressUpdate struct {
	Timestamp  Timestamp
	NetAddress net.IP
}

func (nau *NetAddressUpdate) AppendBinary(b []byte) ([]byte, error) {
	if len(nau.NetAddress) != SizeNetAddress {
		return nil, &errs.SizeError{
			SubjectName:         "NetAddress",
			SubjectActualSize:   len(nau.NetAddress),
			SubjectExpectedSize: SizeNetAddress,
		}
	}

	// Encode Timestamp
	b, err := nau.Timestamp.AppendBinary(b)

	if err != nil {
		return nil, err
	}

	// Encode NetAddress
	b = append(b, nau.NetAddress...)

	return b, nil
}

func (nau *NetAddressUpdate) MarshalBinary() ([]byte, error) {
	b, err := nau.AppendBinary(make([]byte, 0, SizeNetAddressUpdate))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (nau *NetAddressUpdate) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeNetAddressUpdate {
		return &errs.SizeError{
			SubjectName:         "NetAddressUpdate",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeNetAddressUpdate,
		}
	}

	// Decode Timestamp
	if err := nau.Timestamp.UnmarshalBinary(buf); err != nil {
		return err
	}
	buf = buf[SizeTimestamp:]

	// Decode NetAddress
	copy(nau.NetAddress, buf[:SizeNetAddressUpdate])

	return nil
}

// Make a SignedNetAddressUpdate
func (nau *NetAddressUpdate) Sign(privateKey ed25519.PrivateKey) (*SignedNetAddressUpdate, error) {
	data, err := nau.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, data)

	snau := SignedNetAddressUpdate{
		Inner:     nau,
		Signature: signature,
	}

	return &snau, nil
}

type SignedNetAddressUpdate struct {
	Inner     *NetAddressUpdate
	Signature Signature
}

func (snau *SignedNetAddressUpdate) AppendBinary(b []byte) ([]byte, error) {
	if err := snau.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if snau.Inner == nil {
		return nil, &errs.IsNilError{SubjectName: "NetAddressUpdate"}
	}

	// Encode Inner
	b, err := snau.Inner.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Signature
	b = append(b, snau.Signature...)

	return b, nil
}

func (snau *SignedNetAddressUpdate) MarshalBinary() ([]byte, error) {
	b, err := snau.AppendBinary(make([]byte, 0, SizeSignedNetAddressUpdate))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (snau *SignedNetAddressUpdate) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSignedNetAddressUpdate {
		return &errs.SizeError{
			SubjectName:         "SignedNetAddressUpdate",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSignedNetAddressUpdate,
		}
	}

	// Decode Inner
	nauByte := make([]byte, SizeNetAddressUpdate)
	copy(nauByte, buf[:SizeNetAddressUpdate])
	var nau NetAddressUpdate
	if err := nau.UnmarshalBinary(nauByte); err != nil {
		return err
	}
	snau.Inner = &nau

	buf = buf[SizeNetAddressUpdate:]

	// Decode Signature
	snau.Signature = make([]byte, SizeSignature)
	copy(snau.Signature, buf[:SizeSignature])

	return nil
}

func (snau *SignedNetAddressUpdate) Verify(publicKey ed25519.PublicKey) error {
	if err := snau.Signature.CheckSize(); err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedNetAddressUpdate"}, err)
	}

	data, err := snau.Inner.MarshalBinary()
	if err != nil {
		return errors.Join(&errs.VerificationError{SubjectName: "SignedNetAddressUpdate"}, err)
	}

	if !ed25519.Verify(publicKey, data, snau.Signature) {
		return &SignatureVerificationError{
			SubjectName: "SignedNetAddress",
			SigningKey:  publicKey,
			Signature:   snau.Signature,
		}
	}

	return nil
}
