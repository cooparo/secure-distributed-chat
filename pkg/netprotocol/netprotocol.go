package netprotocol

import "github.com/cooparo/secure-distributed-chat/pkg/errs"

const (
	SizeRatchetKey = 32
	SizeVersion    = 1
	SizePacketType = 1
	SizeMainHeader = SizeVersion + SizePacketType
)

type Version uint8
type PacketType uint8

const (
	PacketTypeHeartbeat PacketType = iota
	PacketTypeMessage
	PacketTypeKeyExchangeRequest
	PacketTypeKeyExchangeResponse
	PacketTypeDiscoveryRequest
	PacketTypeDiscoveryResponse
)

type MainHeader struct {
	Version    Version
	PacketType PacketType
}

func (mainhdr *MainHeader) AppendBinary(b []byte) ([]byte, error) {
	// Encode Version
	b = append(b, byte(mainhdr.Version))

	// Encode PacketType
	b = append(b, byte(mainhdr.PacketType))

	return b, nil
}

func (mainhdr *MainHeader) MarshalBinary() ([]byte, error) {
	b, _ := mainhdr.AppendBinary(make([]byte, 0, SizeMainHeader))

	return b, nil
}

func (mainhdr *MainHeader) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != SizeMainHeader {
		return &errs.SizeError{
			SubjectName:         "MainHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: SizeMainHeader,
		}
	}

	// Decode Version
	mainhdr.Version = Version(buf[0])

	buf = buf[SizeVersion:]

	// Decode PacketType
	mainhdr.PacketType = PacketType(buf[0])

	return nil
}
