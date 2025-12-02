package netprotocol

import (
	"crypto/ecdh"

	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeDataLength     = 2
	SizePrevChainCount = 1
	SizeChainCount     = 1
	SizeMessageHeader  = identity.SizeIdentityAddress + SizeDataLength + SizePrevChainCount + SizeChainCount + SizeRatchetKey
)

type MessageHeader struct {
	SendIDAddr     identity.IdentityAddress
	DataLength     uint16
	PrevChainCount uint8
	ChainCount     uint8
	RatchetKey     *ecdh.PublicKey
}

func (msghdr *MessageHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := msghdr.SendIDAddr.CheckSize(); err != nil {
		return nil, err
	}
	if msghdr.RatchetKey == nil {
		return nil, &errs.IsNilError{SubjectName: "RatchetKey"}
	}
	if msghdr.RatchetKey.Curve() != ecdh.X25519() {
		return nil, &errs.DHCurveError{
			SubjectName:          "RatchetKey",
			SubjectActualCurve:   msghdr.RatchetKey.Curve(),
			SubjectExpectedCurve: ecdh.X25519(),
		}
	}

	// Encode IdentityAddress
	b = append(b, msghdr.SendIDAddr...)

	// Encode DataLength
	dataLen := msghdr.DataLength
	b = append(b,
		byte(dataLen>>8),
		byte(dataLen))

	// Encode PrevChainCount
	b = append(b, byte(msghdr.PrevChainCount))

	// Encode ChainCount
	b = append(b, byte(msghdr.ChainCount))

	// Encode RatchetKey
	b = append(b, msghdr.RatchetKey.Bytes()...)

	return b, nil
}

func (msghdr *MessageHeader) MarshalBinary() ([]byte, error) {
	b, err := msghdr.AppendBinary(make([]byte, 0, SizeMessageHeader))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (msghdr *MessageHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeMessageHeader {
		return &errs.SizeError{
			SubjectName:         "MessageHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMessageHeader,
		}
	}

	// Decode SendIDAddr
	msghdr.SendIDAddr = make([]byte, identity.SizeIdentityAddress)
	copy(msghdr.SendIDAddr, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode DataLength
	dataLen := uint16(buf[1]) | uint16(buf[0])<<8
	msghdr.DataLength = dataLen

	buf = buf[SizeDataLength:]

	// Decode PrevChainCount
	msghdr.PrevChainCount = uint8(buf[0])

	buf = buf[SizePrevChainCount:]

	// Decode ChainCount
	msghdr.ChainCount = uint8(buf[0])

	buf = buf[SizeChainCount:]

	// Decode RatchetKey
	rkeyByte := make([]byte, SizeRatchetKey)
	copy(rkeyByte, buf[:SizeRatchetKey])
	curve := ecdh.X25519()
	rkey, _ := curve.NewPublicKey(rkeyByte)
	msghdr.RatchetKey = rkey

	buf = buf[SizeRatchetKey:]

	return nil
}

type Message struct {
	Header *MessageHeader
	Data   []byte
}

func (msg *Message) AppendBinary(b []byte) ([]byte, error) {
	if msg.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	if len(msg.Data) != int(msg.Header.DataLength) {
		return nil, &errs.SizeError{
			SubjectName:         "Data",
			SubjectActualSize:   len(msg.Data),
			SubjectExpectedSize: int(msg.Header.DataLength),
		}
	}

	// Encode Header
	b, err := msg.Header.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Data
	b = append(b, msg.Data...)

	return b, nil
}

func (msg *Message) MarshalBinary() ([]byte, error) {
	if msg.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	sizeMessage := SizeMessageHeader + msg.Header.DataLength
	b, err := msg.AppendBinary(make([]byte, 0, sizeMessage))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (msg *Message) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) < SizeMessageHeader {
		return &errs.MinSizeError{
			SubjectName:         "Message",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMessageHeader,
		}
	}

	// Decode Header
	msghdrByte := make([]byte, SizeMessageHeader)
	copy(msghdrByte, buf[:SizeMessageHeader])
	msghdr := &MessageHeader{}
	if err := msghdr.UnmarshalBinary(msghdrByte); err != nil {
		return err
	}
	msg.Header = msghdr

	buf = buf[SizeMessageHeader:]

	if len(buf) != int(msghdr.DataLength) {
		return &errs.SizeError{
			SubjectName:         "Data",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: int(msghdr.DataLength),
		}
	}

	// Decode Data
	msg.Data = make([]byte, msghdr.DataLength)
	copy(msg.Data, buf[:msghdr.DataLength])

	return nil
}

func (msg *Message) Decrypt(ratchet *doubleratchet.DoubleRatchet) ([]byte, error) {
	if msg.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "MessageHeader"}
	}

	msghdrByte, err := msg.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}

	plaintext, err := ratchet.Decrypt(msg.Header.RatchetKey, msg.Data, msghdrByte)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func MakeMessage(address identity.IdentityAddress, ratchet *doubleratchet.DoubleRatchet, data []byte) (*Message, error) {
	msghdr := &MessageHeader{
		SendIDAddr:     address,
		DataLength:     uint16(doubleratchet.EncryptedSize(data)),
		PrevChainCount: uint8(ratchet.SendChain.PrevMsgCount) + 1,
		ChainCount:     uint8(ratchet.SendChain.MsgCount) + 1,
		RatchetKey:     ratchet.OurKey.PublicKey(),
	}

	msghdrByte, err := msghdr.MarshalBinary()
	if err != nil {
		return nil, err
	}

	ciphertext, err := ratchet.Encrypt(data, msghdrByte)
	if err != nil {
		return nil, err
	}

	msg := &Message{
		Header: msghdr,
		Data:   ciphertext,
	}

	return msg, nil
}
