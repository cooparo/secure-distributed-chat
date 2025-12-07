package ipcprotocol

import "github.com/cooparo/secure-distributed-chat/pkg/errs"

const (
	SizeVersion     = 1
	SizeCommandType = 1
	SizeMainHeader  = SizeVersion + SizeCommandType
)

type Version uint8
type CommandType uint8

const (
	CommandTypeMessageRequest CommandType = iota
	CommandTypeMessageResponse
	CommandTypeSendMessage
	CommandTypeSendMessageAck
	CommandTypeSendMessageNac
)

type MainHeader struct {
	Version Version
	CommandType CommandType
}

func (mainhdr *MainHeader) AppendBinary(b []byte) ([]byte, error) {
	// Encode Version
	b = append(b, byte(mainhdr.Version))

	// Encode CommandType
	b = append(b, byte(mainhdr.CommandType))

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

	// Decode CommandType
	mainhdr.CommandType = CommandType(buf[0])

	return nil
}
