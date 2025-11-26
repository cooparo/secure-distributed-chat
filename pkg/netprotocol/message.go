package netprotocol

import (
	"crypto/ecdh"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeDataLength     = 2
	SizePrevChainCount = 1
	SizeChainCount     = 1
	SizeNonce          = 12
	SizeMessageHeader  = identity.SizeIdentityAddress + SizeDataLength + SizePrevChainCount + SizeChainCount + SizeNonce
)

type MessageHeader struct {
	IdentityAddress identity.IdentityAddress
	DataLength      uint16
	PrevChainCount  uint8
	ChainCount      uint8
	RatchetKey      *ecdh.PublicKey
	Nonce           []byte
}

func (mh *MessageHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := mh.IdentityAddress.CheckSize(); err != nil {
		return nil, err
	}
	if mh.RatchetKey == nil {
		return nil, &errs.IsNilErr{SubjectName: "RatchetKey"}
	}
	if mh.RatchetKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "RatchetKey",
			SubjectActualCurve:   mh.RatchetKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}
	if len(mh.Nonce) != SizeNonce {
		return nil, &errs.SizeError{
			SubjectName:         "Nonce",
			SubjectActualSize:   len(mh.Nonce),
			SubjectExpectedSize: SizeNonce,
		}
	}

	// Encode IdentityAddress
	b = append(b, mh.IdentityAddress...)

	// Encode DataLength
	dl := mh.DataLength
	b = append(b,
		byte(dl>>8),
		byte(dl))

	// Encode PrevChainCount
	b = append(b, byte(mh.PrevChainCount))

	// Encode ChainCount
	b = append(b, byte(mh.ChainCount))

	// Encode RatchetKey
	b = append(b, mh.RatchetKey.Bytes()...)

	// Encode Nonce
	b = append(b, mh.Nonce...)

	return b, nil
}

func (mh *MessageHeader) MarshalBinary() ([]byte, error) {
	b, err := mh.AppendBinary(make([]byte, 0, SizeMessageHeader))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (mh *MessageHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeMessageHeader {
		return &errs.SizeError{
			SubjectName:         "MessageHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMessageHeader,
		}
	}

	// Decode IdentityAddress
	mh.IdentityAddress = make([]byte, identity.SizeIdentityAddress)
	copy(mh.IdentityAddress, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode DataLength
	dl := uint16(buf[1]) | uint16(buf[0])<<8
	mh.DataLength = dl

	buf = buf[SizeDataLength:]

	// Decode PrevChainCount
	mh.PrevChainCount = uint8(buf[0])

	buf = buf[SizePrevChainCount:]

	// Decode ChainCount
	mh.ChainCount = uint8(buf[0])

	buf = buf[SizeChainCount:]

	// Decode RatchetKey
	rkByte := make([]byte, SizeRatchetKey)
	copy(rkByte, buf[:SizeRatchetKey])
	curve := ecdh.X25519()
	rk, _ := curve.NewPublicKey(rkByte)
	mh.RatchetKey = rk

	buf = buf[SizeRatchetKey:]

	// Decode Nonce
	mh.Nonce = make([]byte, SizeNonce)
	copy(mh.Nonce, buf[:SizeNonce])

	return nil
}

type Message struct {
	Header *MessageHeader
	Data   []byte
}

func (m *Message) AppendBinary(b []byte) ([]byte, error) {
	if m.Header == nil {
		return nil, &errs.IsNilErr{SubjectName: "Header"}
	}
	if len(m.Data) != int(m.Header.DataLength) {
		return nil, &errs.SizeError{
			SubjectName:         "Data",
			SubjectActualSize:   len(m.Data),
			SubjectExpectedSize: int(m.Header.DataLength),
		}
	}

	// Encode Header
	b, err := m.Header.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Data
	b = append(b, m.Data...)

	return b, nil
}

func (m *Message) MarshalBinary() ([]byte, error) {
	if m.Header == nil {
		return nil, &errs.IsNilErr{SubjectName: "Header"}
	}
	sizeMessage := SizeMessageHeader + m.Header.DataLength
	b, err := m.AppendBinary(make([]byte, 0, sizeMessage))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (m *Message) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) < SizeMessageHeader {
		return &errs.MinSizeErr{
			SubjectName:         "Message",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMessageHeader,
		}
	}

	// Decode Header
	mhByte := make([]byte, SizeMessageHeader)
	copy(mhByte, buf[:SizeMessageHeader])
	var mh MessageHeader
	if err := mh.UnmarshalBinary(mhByte); err != nil {
		return err
	}
	m.Header = &mh

	buf = buf[SizeMessageHeader:]

	if len(buf) != int(m.Header.DataLength) {
		return &errs.SizeError{
			SubjectName:         "Data",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: int(m.Header.DataLength),
		}
	}

	// Decode Data
	m.Data = make([]byte, m.Header.DataLength)
	copy(m.Data, buf[:m.Header.DataLength])

	return nil
}
