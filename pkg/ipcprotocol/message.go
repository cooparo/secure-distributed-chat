package ipcprotocol

import (
	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeMessageRequestHeader = identity.SizeIdentityAddress

	SizeNumberOfMessages = 2

	SizeMessageSenderAddress   = identity.SizeIdentityAddress
	SizeMessageReceiverAddress = identity.SizeIdentityAddress
	SizeMessageLength          = 2
	SizeMessageResponseHeader  = SizeMessageSenderAddress + SizeMessageReceiverAddress + common.SizeTimestamp + SizeMessageLength
)

type MessageRequestHeader struct {
	Address identity.IdentityAddress
}

type MessageResponseHeader struct {
	SenderAddress   identity.IdentityAddress
	ReceiverAddress identity.IdentityAddress
	Timestamp       common.Timestamp
	MessageLength   uint16
}

type MessageResponsePacket struct {
	Header MessageResponseHeader
	Data   MessageData
}

func (msgreshdr *MessageResponseHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := msgreshdr.ReceiverAddress.CheckSize(); err != nil {
		return nil, err
	}
	if err := msgreshdr.SenderAddress.CheckSize(); err != nil {
		return nil, err
	}

	// Encode ReceiverAddress
	b = append(b, msgreshdr.ReceiverAddress...)
	// Encode SenderAddress
	b = append(b, msgreshdr.SenderAddress...)

	// Encode Timestamp
	var err error
	b, err = msgreshdr.Timestamp.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode MessageLength
	common.Uint16AppendBinary(b, msgreshdr.MessageLength)

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

	// Decode SenderAddress
	msgreshdr.SenderAddress = make([]byte, identity.SizeIdentityAddress)
	copy(msgreshdr.SenderAddress, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode ReceiverAddress
	msgreshdr.ReceiverAddress = make([]byte, identity.SizeIdentityAddress)
	copy(msgreshdr.ReceiverAddress, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode Timestamp
	timestamp := common.Int64UnmarshalBinary(buf[:common.SizeTimestamp])
	msgreshdr.Timestamp = common.Timestamp(timestamp)

	buf = buf[common.SizeTimestamp:]

	// Decode MessageLength
	msglen := common.Uint16UnmarshalBinary(buf[:2])
	msgreshdr.MessageLength = msglen

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

	// Decode Address
	msgreqhdr.Address = make([]byte, identity.SizeIdentityAddress)
	copy(msgreqhdr.Address, buf[:identity.SizeIdentityAddress])

	return nil
}
