package identity

import (
	"crypto/ed25519"
	"net"
)

const (
	TimestampSize              = 8
	NetAddressSize             = 16
	NetAddressUpdateSize       = TimestampSize + NetAddressSize
	SignedNetAddressUpdateSize = NetAddressUpdateSize + SignatureSize
)

type NetAddressUpdate struct {
	Timestamp  int64
	NetAddress net.IP
}

func (nau *NetAddressUpdate) AppendBinary(b []byte) ([]byte, error) {
	if len(nau.NetAddress) != NetAddressSize {
		return nil, &ErrInvalidSize{
			SubjectName: "NetAddress",
			SubjectSize: len(nau.NetAddress),
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
		byte(t),
	)

	// Encode NetAddress
	b = append(b, nau.NetAddress...)

	return b, nil
}

func (nau *NetAddressUpdate) MarshalBinary() ([]byte, error) {
	b, err := nau.AppendBinary(make([]byte, NetAddressUpdateSize))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (nau *NetAddressUpdate) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != NetAddressUpdateSize {
		return &ErrInvalidSize{SubjectName: "NetAddressUpdate",
			SubjectSize: len(buf)}
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

	buf = buf[TimestampSize:]

	// Decode NetAddress
	copy(nau.NetAddress, buf[:NetAddressUpdateSize])

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
	Signature        []byte
}

func (snau *SignedNetAddressUpdate) AppendBinary(b []byte) ([]byte, error) {
	if len(snau.Signature) != SignatureSize {
		return nil, &ErrInvalidSize{SubjectName: "Signature",
			SubjectSize: len(snau.Signature)}
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
	b, err := snau.AppendBinary(make([]byte, SignedNetAddressUpdateSize))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (snau *SignedNetAddressUpdate) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SignedNetAddressUpdateSize {
		return &ErrInvalidSize{
			SubjectName: "SignedNetAddressUpdate",
			SubjectSize: len(buf),
		}
	}

	// Decode NetAddressUpdate
	nauByte := make([]byte, NetAddressUpdateSize)
	copy(nauByte, buf[:NetAddressUpdateSize])
	var nau NetAddressUpdate
	nau.UnmarshalBinary(nauByte)
	snau.NetAddressUpdate = &nau

	buf = buf[NetAddressUpdateSize:]

	// Decode Signature
	snau.Signature = make([]byte, SignatureSize)
	copy(snau.Signature, buf[:SignatureSize])

	return nil
}
