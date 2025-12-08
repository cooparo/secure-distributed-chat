package ipcprotocol

import (
	"fmt"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeMessageRequestHeader = identity.SizeIdentityAddress

	SizeNumberOfMessages = 2

	SizeMessageSenderAddress   = identity.SizeIdentityAddress
	SizeMessageReceiverAddress = identity.SizeIdentityAddress
	SizeTimestamp              = 8
	SizeMessageContentLength   = 2
	SizeMessageResponseHeader  = SizeMessageSenderAddress + SizeMessageReceiverAddress + SizeTimestamp + SizeMessageContentLength
)

type MessageRequestHeader struct {
	Address identity.IdentityAddress
}

type NumberOfMesseges uint16

type Timestamp int64

type MessageData []byte

type MessageResponseHeader struct {
	ReceiverAddress      identity.IdentityAddress
	SenderAddress        identity.IdentityAddress
	Timestamp            Timestamp
	MessageContentLength uint16
}

type MessageResponsePacket struct {
	HeaderResponce MessageResponseHeader
	Data           MessageData
}

func (msgdata MessageData) AppendBinary(b []byte) ([]byte, error) {
	return append(b, msgdata...), nil
}

func (msgdata *MessageData) UnmarshalBinary(b []byte, datalen uint16) error {
	buf := b
	*msgdata = make([]byte, datalen)
	copy(*msgdata, buf)
	return nil
}

func (msgrespaket *MessageResponsePacket) MarshalBinary() ([]byte, error) {
	b, err := msgrespaket.HeaderResponce.MarshalBinary()
	if err != nil {
		return nil, err
	}

	b, _ = msgrespaket.Data.AppendBinary(b)
	return b, nil
}

func (msgrespaket *MessageResponsePacket) UnmarshalBinary(b []byte) error {
	buf := b
	if len(buf) < SizeMessageResponseHeader {
		return fmt.Errorf("buffer too small for header")
	}

	headerBuf := buf[:SizeMessageResponseHeader]
	err := msgrespaket.HeaderResponce.UnmarshalBinary(headerBuf)
	if err != nil {
		return err
	}

	return nil
}

func (msgreshdr *MessageResponseHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := msgreshdr.ReceiverAddress.CheckSize(); err != nil {
		return nil, err
	}
	if err := msgreshdr.SenderAddress.CheckSize(); err != nil {
		return nil, err
	}

	b = append(b, msgreshdr.SenderAddress...)

	b = append(b, msgreshdr.ReceiverAddress...)

	var err error
	b, err = msgreshdr.Timestamp.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	b = append(b, byte(msgreshdr.MessageContentLength))

	return b, nil
}

func (msgreshdr *MessageResponseHeader) MarshalBinary() ([]byte, error) {
	b, err := msgreshdr.AppendBinary(make([]byte, 0, SizeMessageResponseHeader))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (msgreshdr *MessageResponseHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeMessageResponseHeader {
		return &errs.SizeError{
			SubjectName:         "SizeMessageResponseHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMessageResponseHeader,
		}
	}

	msgreshdr.ReceiverAddress = make([]byte, identity.SizeIdentityAddress)
	copy(msgreshdr.ReceiverAddress, buf[:identity.SizeIdentityAddress])
	buf = buf[identity.SizeIdentityAddress:]

	msgreshdr.SenderAddress = make([]byte, identity.SizeIdentityAddress)
	copy(msgreshdr.SenderAddress, buf[:identity.SizeIdentityAddress])

	if err := msgreshdr.Timestamp.UnmarshalBinary(buf); err != nil {
		return err
	}
	buf = buf[SizeTimestamp:]

	dataLen := uint16(buf[1]) | uint16(buf[0])<<8
	msgreshdr.MessageContentLength = dataLen

	return nil
}

func (msgreqhdr *MessageRequestHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := msgreqhdr.Address.CheckSize(); err != nil {
		return nil, err
	}

	// Encode Address
	b = append(b, msgreqhdr.Address...)

	return b, nil
}

func (msgreqhdr *MessageRequestHeader) MarshalBinary() ([]byte, error) {
	b, err := msgreqhdr.AppendBinary(make([]byte, 0, SizeMessageRequestHeader))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (msgreqhdr *MessageRequestHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeMessageRequestHeader {
		return &errs.SizeError{
			SubjectName:         "MessageRequestHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMessageRequestHeader,
		}
	}

	msgreqhdr.Address = make([]byte, identity.SizeIdentityAddress)
	copy(msgreqhdr.Address, buf[:identity.SizeIdentityAddress])

	return nil
}

func (t Timestamp) AppendBinary(b []byte) ([]byte, error) {
	return append(b,
		byte(t>>56),
		byte(t>>48),
		byte(t>>40),
		byte(t>>32),
		byte(t>>24),
		byte(t>>16),
		byte(t>>8),
		byte(t)), nil
}

func (t Timestamp) UnmarshalBinary(b []byte) error {
	ts := int64(b[7]) |
		int64(b[6])<<8 |
		int64(b[5])<<16 |
		int64(b[4])<<24 |
		int64(b[3])<<32 |
		int64(b[2])<<40 |
		int64(b[1])<<48 |
		int64(b[0])<<56

	t = Timestamp(ts)
	return nil
}
func (msgcount NumberOfMesseges) AppendBinary(b []byte) ([]byte, error) {
	v := uint16(msgcount)

	return append(b,
		byte(v>>8),
		byte(v),
	), nil
}

func (msgcount NumberOfMesseges) MarshalBinary() ([]byte, error) {
	b, err := msgcount.AppendBinary(make([]byte, 0, SizeTimestamp))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (msgcount NumberOfMesseges) UnmarshalBinary(b []byte) error {
	buf := b
	if len(buf) != SizeNumberOfMessages {
		return &errs.SizeError{
			SubjectName:         "NumberOfMesseges",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeNumberOfMessages,
		}

	}

	dataLen := uint16(buf[1]) | uint16(buf[0])<<8
	msgcount = NumberOfMesseges(dataLen)
	return nil
}
