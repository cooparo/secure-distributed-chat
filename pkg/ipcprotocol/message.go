package ipcprotocol

import (
	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeMessageSenderAddress   = identity.SizeIdentityAddress
	SizeMessageReceiverAddress = identity.SizeIdentityAddress
	SizeMessageLength          = 2
	SizeMessageHeader          = SizeMessageSenderAddress + SizeMessageReceiverAddress + common.SizeTimestamp + SizeMessageLength
)

type MessageHeader struct {
	SenderAddress   identity.IdentityAddress
	ReceiverAddress identity.IdentityAddress
	Timestamp       common.Timestamp
	MessageLength   uint16
}

func (msghdr *MessageHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := msghdr.SenderAddress.CheckSize(); err != nil {
		return nil, err
	}
	if err := msghdr.ReceiverAddress.CheckSize(); err != nil {
		return nil, err
	}

	// Encode SenderAddress
	b = append(b, msghdr.SenderAddress...)

	// Encode ReceiverAddress
	b = append(b, msghdr.ReceiverAddress...)

	// Encode Timestamp
	b = common.Int64AppendBinary(b, int64(msghdr.Timestamp))

	// Encode MessageLength
	b = common.Uint16AppendBinary(b, msghdr.MessageLength)

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

	// Decode SenderAddress
	msghdr.SenderAddress = make([]byte, identity.SizeIdentityAddress)
	copy(msghdr.SenderAddress, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode ReceiverAddress
	msghdr.ReceiverAddress = make([]byte, identity.SizeIdentityAddress)
	copy(msghdr.ReceiverAddress, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode Timestamp
	msghdr.Timestamp = common.Timestamp(common.Int64UnmarshalBinary(buf[:common.SizeTimestamp]))

	buf = buf[common.SizeTimestamp:]

	// Decode MessageLength
	msghdr.MessageLength = common.Uint16UnmarshalBinary(buf[:SizeMessageLength])

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
	if len(msg.Data) != int(msg.Header.MessageLength) {
		return nil, &errs.SizeError{
			SubjectName:         "Data",
			SubjectActualSize:   len(msg.Data),
			SubjectExpectedSize: int(msg.Header.MessageLength),
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
	sizeMessage := SizeMessageHeader + msg.Header.MessageLength
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
			SubjectExpectedSize: SizeMessageResponseHeader,
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

	buf = buf[SizeMessageResponseHeader:]

	if len(buf) != int(msghdr.MessageLength) {
		return &errs.SizeError{
			SubjectName:         "Data",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: int(msghdr.MessageLength),
		}
	}

	// Decode Data
	msg.Data = make([]byte, msghdr.MessageLength)
	copy(msg.Data, buf[:msghdr.MessageLength])

	return nil
}
