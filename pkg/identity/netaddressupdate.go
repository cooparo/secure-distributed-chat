package identity

import (
	"crypto/ed25519"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
)

const (
	SizeTimestamp              = 8
	SizeNetAddress             = 16
	SizeNetAddressUpdate       = SizeTimestamp + SizeNetAddress
	SizeSignedNetAddressUpdate = SizeNetAddressUpdate + SizeSignature
)

type NetAddressUpdate struct {
	Timestamp  int64
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
	t := nau.Timestamp
	b = append(b,
		byte(t>>56),
		byte(t>>48),
		byte(t>>40),
		byte(t>>32),
		byte(t>>24),
		byte(t>>16),
		byte(t>>8),
		byte(t))

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
	t := int64(b[7]) |
		int64(b[6])<<8 |
		int64(b[5])<<16 |
		int64(b[4])<<24 |
		int64(b[3])<<32 |
		int64(b[2])<<40 |
		int64(b[1])<<48 |
		int64(b[0])<<56
	nau.Timestamp = t

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
		NetAddressUpdate: nau,
		Signature:        signature,
	}

	return &snau, nil
}

type SignedNetAddressUpdate struct {
	NetAddressUpdate *NetAddressUpdate
	Signature        Signature
}

func (snau *SignedNetAddressUpdate) AppendBinary(b []byte) ([]byte, error) {
	if err := snau.Signature.CheckSize(); err != nil {
		return nil, err
	}
	if snau.NetAddressUpdate == nil {
		return nil, &errs.IsNilErr{SubjectName: "NetAddressUpdate"}
	}

	// Encode NetAddressUpdate
	b, err := snau.NetAddressUpdate.AppendBinary(b)
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

	// Decode NetAddressUpdate
	nauByte := make([]byte, SizeNetAddressUpdate)
	copy(nauByte, buf[:SizeNetAddressUpdate])
	var nau NetAddressUpdate
	if err := nau.UnmarshalBinary(nauByte); err != nil {
		return err
	}
	snau.NetAddressUpdate = &nau

	buf = buf[SizeNetAddressUpdate:]

	// Decode Signature
	snau.Signature = make([]byte, SizeSignature)
	copy(snau.Signature, buf[:SizeSignature])

	return nil
}
