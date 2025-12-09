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

func (msgsendhdr *SendMessageHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := msgsendhdr.PeerAddress.CheckSize(); err != nil {
		return nil, err
	}

	// Encode PeerAddress
	b = append(b, msgsendhdr.PeerAddress...)

	// Encode MessageLength
	b = append(b, byte(msgsendhdr.MessageLength))

	return b, nil
}

func (msgsendhdr *SendMessageHeader) MarshalBinary() ([]byte, error) {
	b, err := msgsendhdr.AppendBinary(make([]byte, 0, SizeSendMessageHeader))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (msgreshdr *SendMessageHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeSendMessageHeader {
		return &errs.SizeError{
			SubjectName:         "SizeSendMessageHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeSendMessageHeader,
		}
	}

	// Decode PeerAddress
	msgreshdr.PeerAddress = make([]byte, identity.SizeIdentityAddress)
	copy(msgreshdr.PeerAddress, buf[:identity.SizeIdentityAddress])

	buf = buf[identity.SizeIdentityAddress:]

	// Decode MessageLength
	msglen := common.Uint16UnmarshalBinary(buf[:SizeMessageLength])
	msgreshdr.MessageLength = msglen

	return nil
}
