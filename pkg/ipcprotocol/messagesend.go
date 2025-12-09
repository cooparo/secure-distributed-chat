package ipcprotocol

import (
	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizeSendMessageHeader = identity.SizeIdentityAddress + SizeMessageLength
)

type SendMessageHeader struct {
	PeerAddress   identity.IdentityAddress
	MessageLength uint16
}

func (sendmsghdr *SendMessageHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := sendmsghdr.PeerAddress.CheckSize(); err != nil {
		return nil, err
	}

	// Encode PeerAddress
	b = append(b, sendmsghdr.PeerAddress...)

	// Encode MessageLength
	b = common.Uint16AppendBinary(b, sendmsghdr.MessageLength)

	return b, nil
}

func (sendmsghdr *SendMessageHeader) MarshalBinary() ([]byte, error) {
	b, err := sendmsghdr.AppendBinary(make([]byte, 0, SizeSendMessageHeader))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (sendmsghdr *SendMessageHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSendMessageHeader {
		return &errs.SizeError{
			SubjectName:         "SizeSendMessageHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSendMessageHeader,
		}
	}

	// Decode PeerAddress
	sendmsghdr.PeerAddress = make([]byte, identity.SizeIdentityAddress)
	copy(sendmsghdr.PeerAddress, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode MessageLength
	sendmsghdr.MessageLength = common.Uint16UnmarshalBinary(buf[:SizeMessageLength])

	return nil
}

type SendMessage struct {
	Header *SendMessageHeader
	Data   []byte
}

func (sendmsg *SendMessage) AppendBinary(b []byte) ([]byte, error) {
	if sendmsg.Header == nil {
		return nil, &errs.IsNilError{SubjectName: "Header"}
	}

	// Encode Header
	b, err := sendmsg.Header.AppendBinary(b)
	if err != nil {
		return nil, err
	}

	// Encode Message
	b = append(b, sendmsg.Data...)

	return b, nil
}

func (sendmsg *SendMessage) MarshalBinary() ([]byte, error) {
	b, err := sendmsg.AppendBinary(nil)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (sendmsg *SendMessage) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) < SizeSendMessageHeader {
		return &errs.MinSizeError{
			SubjectName:         "SendMessage",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSendMessageHeader,
		}
	}

	// Decode Header
	sendmsghdrByte := make([]byte, SizeSendMessageHeader)
	copy(sendmsghdrByte, buf[:SizeSendMessageHeader])
	sendmsghdr := &SendMessageHeader{}
	if err := sendmsghdr.UnmarshalBinary(sendmsghdrByte); err != nil {
		return err
	}
	sendmsg.Header = sendmsghdr

	buf = buf[SizeSendMessageHeader:]

	if len(buf) != int(sendmsghdr.MessageLength) {
		return &errs.SizeError{
			SubjectName:         "Data",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: int(sendmsghdr.MessageLength),
		}
	}

	// Decode Message
	sendmsg.Data = make([]byte, sendmsghdr.MessageLength)
	copy(sendmsg.Data, buf[:sendmsghdr.MessageLength])

	return nil
}
