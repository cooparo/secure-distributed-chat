package ipcprotocol

import (
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	SizePeerAddres        = identity.SizeIdentityAddress
	SizeSendMessageHeader = SizePeerAddres + SizeMessageContentLength
)

type SendMessageHeader struct {
	PeerAddres           identity.IdentityAddress
	MessageContentLength uint16
}

func (msgsendhdr *SendMessageHeader) AppendBinary(b []byte) ([]byte, error) {
	if err := msgsendhdr.PeerAddres.CheckSize(); err != nil {
		return nil, err
	}
	b = append(b, msgsendhdr.PeerAddres...)
	b = append(b, byte(msgsendhdr.MessageContentLength))

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

	msgreshdr.PeerAddres = make([]byte, identity.SizeIdentityAddress)
	buf = buf[:identity.SizeIdentityAddress]

	dataLen := uint16(buf[1]) | uint16(buf[0])<<8
	msgreshdr.MessageContentLength = dataLen

	return nil
}
