package ipc

import (
	"encoding/binary"
	"fmt"
)

const (
	ipcProtocolVersion uint8 = 1
	headerSize               = 4
	maxMsgPktSize            = maxCmdPayloadSize - headerSize - 2 // cmdSize - headerSize - size of the uint16 msgPktLen
)

type Header struct {
	version          uint8
	cmdType          Cmd
	cmdPayloadLenght uint16
}

func NewHeader(cmdType Cmd) *Header {
	return &Header{
		version:          ipcProtocolVersion,
		cmdType:          cmdType,
		cmdPayloadLenght: 0, // Will be computed in the serialization process
	}
}

func (h *Header) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 4)

	buf[0] = h.version
	buf[1] = uint8(h.cmdType)
	binary.BigEndian.PutUint16(buf[2:4], h.cmdPayloadLenght)

	return buf, nil
}

func (h *Header) UnmarshalBinary(b []byte) error {
	h.version = uint8(b[0])
	h.cmdType = Cmd(b[1])
	h.cmdPayloadLenght = binary.BigEndian.Uint16(b[2:4])

	return nil
}

type Message string

func (m *Message) MarshalBinary() ([]byte, error) {
	return []byte(*m), nil
}

func (m *Message) UnmarshalBinary(b []byte) error {
	*m = Message(string(b))
	return nil
}

// TODO: use the db format
type MsgPacket struct {
	content Message
}

func (m *MsgPacket) MarshalBinary() ([]byte, error) {
	var (
		contentBytes, err = m.content.MarshalBinary()
		contentLength     = uint32(len(contentBytes))
	)

	if err != nil {
		return nil, err
	}

	if contentLength > uint32(maxMsgPktSize) {
		return nil, fmt.Errorf("ipc msg packet: packet too large")
	}

	// Serialize
	buf := make([]byte, 2+contentLength)
	binary.BigEndian.PutUint16(buf[:2], uint16(contentLength))
	copy(buf[2:], contentBytes)

	return buf, nil
}

// UnmarshalBinary Returns how many bytes has read
func (m *MsgPacket) UnmarshalBinary(b []byte) (uint16, error) {
	// MsgPacket Length
	n := binary.BigEndian.Uint16(b[:2]) + 2

	m.content.UnmarshalBinary(b[2:n])
	return n, nil
}
