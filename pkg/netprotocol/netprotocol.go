package netprotocol

import "github.com/cooparo/secure-distributed-chat/pkg/errs"

const (
	SizeRatchetKey = 32
	SizeVersion    = 1
	SizePacketType = 2
	SizeMainHeader = SizeVersion + SizePacketType
)

type Version uint8
type PacketType uint8

const (
	PacketTypeHeartbeat PacketType = iota
	PacketTypeMessage
	PacketTypeKeyExchangeRequest
	PacketTypeKeyExchangeResponse
)

type MainHeader struct {
	Version    Version
	PacketType PacketType
}

func (mh *MainHeader) AppendBinary(b []byte) ([]byte, error) {
	// Encode Version
	b = append(b, byte(mh.Version))

	// Encode PacketType
	b = append(b, byte(mh.PacketType))

	return b, nil
}

func (mh *MainHeader) MarshalBinary() ([]byte, error) {
	b, _ := mh.AppendBinary(make([]byte, 0, SizeMainHeader))

	return b, nil
}

func (mh *MainHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeMainHeader {
		return &errs.ErrInvalidSize{
			SubjectName:         "MainHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMainHeader,
		}
	}

	// Decode Version
	mh.Version = Version(b[0])

	buf = buf[SizeVersion:]

	// Decode PacketType
	mh.PacketType = PacketType(b[0])

	return nil
}
