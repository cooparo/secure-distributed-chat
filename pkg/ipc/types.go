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

type Serializer interface {
	ToBytes() ([]byte, error)
}

type Deserializer interface {
	FromBytes([]byte) error
}

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

func (h *Header) ToBytes() ([]byte, error) {
	buf := make([]byte, 4)

	buf[0] = h.version
	buf[1] = uint8(h.cmdType)
	binary.BigEndian.PutUint16(buf[2:4], h.cmdPayloadLenght)

	return buf, nil
}

func (h *Header) FromBytes(b []byte) error {
	h.version = uint8(b[0])
	h.cmdType = Cmd(b[1])
	h.cmdPayloadLenght = binary.BigEndian.Uint16(b[2:4])

	return nil
}

type Message string

func (m *Message) ToBytes() ([]byte, error) {
	return []byte(*m), nil
}

func (m *Message) FromBytes(b []byte) error {
	*m = Message(string(b))
	return nil
}

type MsgPacket struct {
	content Message
}

func (m *MsgPacket) ToBytes() ([]byte, error) {
	var (
		contentBytes, err = m.content.ToBytes()
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

// FromBytes Returns how many bytes has read
func (m *MsgPacket) FromBytes(b []byte) (uint16, error) {
	// MsgPacket Length
	n := binary.BigEndian.Uint16(b[:2]) + 2

	m.content.FromBytes(b[2:n])
	return n, nil
}
