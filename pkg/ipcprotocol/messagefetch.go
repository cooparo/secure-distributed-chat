package ipcprotocol

import (
	"fmt"

	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeMessageRequestHeader  = identity.SizeIdentityAddress
	SizeMessageCount          = 2
	SizeMessageResponseHeader = SizeMessageCount
)

type MessageRequestHeader struct {
	Address identity.IdentityAddress
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

type MessageResponseHeader struct {
	MessageCount uint16
}

func (msgresphdr *MessageResponseHeader) AppendBinary(b []byte) ([]byte, error) {
	// Encode MessageCount
	b = common.Uint16AppendBinary(b, msgresphdr.MessageCount)

	return b, nil
}

func (msgresphdr *MessageResponseHeader) MarshalBinary() ([]byte, error) {
	b, _ := msgresphdr.AppendBinary(make([]byte, 0, SizeMessageResponseHeader))

	return b, nil
}

func (msgresphdr *MessageResponseHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeMessageHeader {
		return &errs.SizeError{
			SubjectName:         "MessageResponseHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMessageHeader,
		}
	}

	// Decode MessageCount
	msgresphdr.MessageCount = common.Uint16UnmarshalBinary(buf[:SizeMessageCount])

	return nil
}

type MessageResponse struct {
	Header   *MessageResponseHeader
	Messages []*Message
}

func (msgresp *MessageResponse) AppendBinary(b []byte) ([]byte, error) {
	if msgresp.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}
	if len(msgresp.Messages) != int(msgresp.Header.MessageCount) {
		return nil, &errs.SizeError{
			SubjectName:         "MessageCount",
			SubjectActualSize:   len(msgresp.Messages),
			SubjectExpectedSize: int(msgresp.Header.MessageCount),
		}
	}

	// Encode Header
	b, err := msgresp.Header.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Messages
	for idx, msg := range msgresp.Messages {
		if msg == nil {
			return nil, &errs.IsNilError{SubjectName: fmt.Sprintf("Messages[%d]", idx)}
		}
		b, err = msg.AppendBinary(b)
		if err != nil {
			return nil, err
		}
	}

	return b, nil
}

func (msgresp *MessageResponse) MarshalBinary() ([]byte, error) {
	b, err := msgresp.AppendBinary(nil)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (msgresp *MessageResponse) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) < SizeMessageResponseHeader {
		return &errs.MinSizeError{
			SubjectName:         "MessageResponse",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMessageResponseHeader,
		}
	}

	// Decode Header
	msgresphdrByte := make([]byte, SizeMessageResponseHeader)
	copy(msgresphdrByte, buf[:SizeMessageResponseHeader])
	msgresphdr := &MessageResponseHeader{}
	if err := msgresphdr.UnmarshalBinary(msgresphdrByte); err != nil {
		return err
	}
	msgresp.Header = msgresphdr

	buf = buf[SizeMessageResponseHeader:]

	// Decode Messages
	msgresp.Messages = make([]*Message, 0, msgresphdr.MessageCount)

	for range msgresphdr.MessageCount {
		msg := &Message{}

		msghdrByte := make([]byte, SizeMessageHeader)
		copy(msghdrByte, buf[:SizeMessageHeader])
		msghdr := &MessageHeader{}
		if err := msghdr.UnmarshalBinary(msghdrByte); err != nil {
			return err
		}

		buf = buf[SizeMessageHeader:]

		msg.Header = msghdr

		msg.Data = make([]byte, msghdr.MessageLength)
		copy(msg.Data, buf[:msghdr.MessageLength])

		buf = buf[msghdr.MessageLength:]

		msgresp.Messages = append(msgresp.Messages, msg)
	}

	return nil
}
