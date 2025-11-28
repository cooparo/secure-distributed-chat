package ipcprotocol

import (
	"encoding/binary"
	"os"
	"path/filepath"

	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
)

const (
	IpcProtocolVersion = 1

	IpcVersionSize = 1
	IpcCmdTypeSize = 1
	IpcHeaderSize  = IpcVersionSize + IpcCmdTypeSize

	IpcMaxMsgSize       = int(^uint16(0)) // 65535
	IpcLenMsgSize       = 2
	IpcTimestampSize    = 8
	IpcMsgPktHeaderSize = identity.SizeIdentityAddress*2 + IpcTimestampSize + IpcLenMsgSize
)

type Version uint8
type CmdType uint8

const (
	CmdTypeMsgReq CmdType = iota
	CmdTypeMsgResp
	CmdTypeSendMsg
	CmdTypeSendMsgAck
	CmdTypeSendMsgNack
)

// DefaultSocketPath returns the standard location for the socket
func DefaultSocketPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = "/tmp"
	}
	return filepath.Join(dir, "grat.sock")
}

type Header struct {
	Version Version
	CmdType CmdType
}

func NewHeader(ct CmdType) *Header {
	return &Header{
		Version: IpcProtocolVersion,
		CmdType: ct,
	}
}

func (h *Header) AppendBinary(b []byte) ([]byte, error) {
	// Encode Version
	b = append(b, byte(h.Version))

	// Encode Command Type
	b = append(b, byte(h.CmdType))

	return b, nil
}

func (h *Header) MarshalBinary() ([]byte, error) {
	b, _ := h.AppendBinary(make([]byte, 0, IpcHeaderSize))

	return b, nil
}

func (h *Header) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) != IpcHeaderSize {
		return &errs.SizeError{
			SubjectName:         "IpcHeader",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: IpcHeaderSize,
		}
	}

	// Decode Version
	h.Version = Version(b[0])

	buf = buf[IpcVersionSize:]

	// Decode Command Type
	h.CmdType = CmdType(buf[0])

	return nil
} // End - Header

type Message string

func (m *Message) AppendBinary(b []byte) ([]byte, error) {
	length := len(*m)

	if length > IpcMaxMsgSize {
		return nil, &errs.MaxSizeError{
			SubjectName:         "IpcMessage",
			SubjectActualSize:   length,
			SubjectExpectedSize: IpcMaxMsgSize,
		}
	}

	// Encode message length
	b = binary.BigEndian.AppendUint16(b, uint16(length))

	// Encode message
	b = append(b, *m...)

	return b, nil
}

func (m *Message) MarshalBinary() ([]byte, error) {
	return m.AppendBinary(make([]byte, 0, IpcLenMsgSize+len(*m)))
}

func (m *Message) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) < IpcLenMsgSize {
		return &errs.MinSizeError{
			SubjectName:         "IpcMessage",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: IpcLenMsgSize,
		}
	}

	// Decode message length
	length := int(binary.BigEndian.Uint16(buf[:IpcLenMsgSize]))
	buf = buf[IpcLenMsgSize:]

	if len(buf) < length {
		return &errs.MinSizeError{
			SubjectName:         "IpcMessage",
			SubjectActualSize:   len(buf),
			SubjectExpectedSize: length,
		}
	}

	// Decode message content
	*m = Message(buf[:length])

	return nil
} // End - Message

type MsgPacket struct {
	Timestamp int64
	Receiver  identity.IdentityAddress
	Sender    identity.IdentityAddress
	Message   Message
}

func (mp *MsgPacket) AppendBinary(b []byte) ([]byte, error) {
	// Encode timestamp
	t := mp.Timestamp
	b = append(b,
		byte(t>>56),
		byte(t>>48),
		byte(t>>40),
		byte(t>>32),
		byte(t>>24),
		byte(t>>16),
		byte(t>>8),
		byte(t))

	// Encode receiver identity
	b = append(b, mp.Receiver...)

	// Encode sender identity
	b = append(b, mp.Sender...)

	// Encode message
	b, err := mp.Message.AppendBinary(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func (mp *MsgPacket) MarshalBinary() ([]byte, error) {
	b, err := mp.AppendBinary(make([]byte, 0, IpcMsgPktHeaderSize+len(mp.Message)))

	if err != nil {
		return nil, err
	}

	return b, nil
}

func (mp *MsgPacket) UnmarshalBinary(b []byte) error {
	buf := b

	// Decode Timestamp
	t := int64(b[7]) |
		int64(b[6])<<8 |
		int64(b[5])<<16 |
		int64(b[4])<<24 |
		int64(b[3])<<32 |
		int64(b[2])<<40 |
		int64(b[1])<<48 |
		int64(b[0])<<56
	mp.Timestamp = t

	buf = buf[IpcTimestampSize:]

	// Decode reveiver identity
	mp.Receiver = buf[:identity.SizeIdentityAddress]
	buf = buf[identity.SizeIdentityAddress:]

	// Decode sender identity
	mp.Sender = buf[:identity.SizeIdentityAddress]
	buf = buf[identity.SizeIdentityAddress:]

	// Decode message
	mp.Message.UnmarshalBinary(buf)

	return nil
} // End - Message Packet
