package ipcprotocol

import (
	"encoding/binary"
	"fmt"
)

// TODO: use correct error handling

const (
	IpcNoMsgRespPacketSize     = 2 // Size of "# of Messages" integer in MsgRespPacket
	IpcHeaderMsgRespPacketSize = IpcNoMsgRespPacketSize
)

type MsgRespPacketHeader uint16

type MsgRespPacket struct {
	Header              Header
	MsgRespPacketHeader MsgRespPacketHeader
	MsgPackets          []MsgPacket
}

func NewMsgRespPacket(messages []MsgPacket) *MsgRespPacket {
	noMessages := len(messages)

	return &MsgRespPacket{
		Header:              *NewHeader(CmdTypeMsgResp),
		MsgRespPacketHeader: MsgRespPacketHeader(noMessages),
		MsgPackets:          messages,
	}
}

func (mrp *MsgRespPacket) AppendBinary(b []byte) ([]byte, error) {
	// Encode header
	b, err := mrp.Header.AppendBinary(b)

	if err != nil {
		return nil, err
	}

	// Encode # of message (MsgRespPacketHeader)
	n := uint16(mrp.MsgRespPacketHeader)
	b = binary.BigEndian.AppendUint16(b, n)

	// Encode messages
	for _, m := range mrp.MsgPackets {
		b, err = m.AppendBinary(b)

		if err != nil {
			return nil, err
		}
	}

	return b, nil
}

func (mrp *MsgRespPacket) MarshalBinary() ([]byte, error) {
	// WARNING: not sure this is the right way to do this
	payloadSize := 2 * len(mrp.MsgPackets) // 2 bytes for each Message header

	// Compute the byte len of every message
	for _, m := range mrp.MsgPackets {
		payloadSize += len(m.Message)
	}

	return mrp.AppendBinary(make([]byte, 0, payloadSize+IpcHeaderMsgRespPacketSize+IpcHeaderSize))
}

func (mrp *MsgRespPacket) UnmarshalBinary(b []byte) error {
	buf := b

	if len(buf) < IpcHeaderMsgRespPacketSize {
		return fmt.Errorf("ipc msg resp packet: buffer too short for header")
	}

	// Decode # of messages
	mrp.MsgRespPacketHeader = MsgRespPacketHeader(binary.BigEndian.Uint16(buf))
	buf = buf[IpcNoMsgRespPacketSize:]

	var messages []MsgPacket
	for i := 0; i < int(mrp.MsgRespPacketHeader); i++ {
		var msgPacket MsgPacket

		// Decode the message
		msgPacket.UnmarshalBinary(buf)
		bytesRead := IpcLenMsgSize + len(msgPacket.Message)
		buf = buf[bytesRead:]

		messages = append(messages, msgPacket)
	}
	mrp.MsgPackets = messages

	return nil
} // End - Message Response Packet

type MsgReqPacket struct {
	Header Header
}

func NewMsgReqPacket() *MsgReqPacket {
	h := NewHeader(CmdTypeMsgReq)

	return &MsgReqPacket{
		Header: *h,
	}
}

func (mrp *MsgReqPacket) AppendBinary(b []byte) ([]byte, error) {
	b, err := mrp.Header.AppendBinary(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func (mrp *MsgReqPacket) MarshalBinary() ([]byte, error) {
	return mrp.AppendBinary(make([]byte, 0, IpcHeaderSize))
}

func (mrp *MsgReqPacket) UnmarshalBinary(b []byte) error {
	buf := b

	if err := mrp.Header.UnmarshalBinary(buf); err != nil {
		return err
	}

	return nil
} // End - Message Request Packet

type SendMsgPacket struct {
	Header    Header
	MsgPacket MsgPacket
}

func NewSendMsgPacket(p MsgPacket) *SendMsgPacket {
	h := NewHeader(CmdTypeSendMsg)

	return &SendMsgPacket{
		Header:    *h,
		MsgPacket: p,
	}
}

func (p *SendMsgPacket) AppendBinary(b []byte) ([]byte, error) {
	b, err := p.Header.AppendBinary(b)

	if err != nil {
		return nil, err
	}

	b, err = p.MsgPacket.AppendBinary(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func (p *SendMsgPacket) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(make([]byte, 0, IpcMsgPktHeaderSize+len(p.MsgPacket.Message)))
}

func (p *SendMsgPacket) UnmarshalBinary(b []byte) error {
	buf := b

	p.Header.UnmarshalBinary(buf)
	buf = buf[IpcHeaderSize:]

	p.MsgPacket.UnmarshalBinary(buf)

	return nil
} // End - Send Message Packet

type SendMsgAckPacket struct {
	Header Header
}

func NewSendMsgAckPacket() *SendMsgAckPacket {
	h := NewHeader(CmdTypeSendMsgAck)

	return &SendMsgAckPacket{
		Header: *h,
	}
}

func (p *SendMsgAckPacket) AppendBinary(b []byte) ([]byte, error) {
	p.Header.AppendBinary(b)
	return b, nil
}

func (p *SendMsgAckPacket) MarshalBinary() ([]byte, error) {
	buf, err := p.Header.MarshalBinary()

	if err != nil {
		return nil, err
	}

	return buf, nil
}

func (p *SendMsgAckPacket) UnmarshalBinary(b []byte) error {
	p.Header.UnmarshalBinary(b)
	return nil
} // End - Send Message ACK Packet

type SendMsgNackPacket struct {
	Header Header
}

func NewSendMsgNackPacket() *SendMsgNackPacket {
	h := NewHeader(CmdTypeSendMsgNack)

	return &SendMsgNackPacket{
		Header: *h,
	}
}

func (p *SendMsgNackPacket) AppendBinary(b []byte) ([]byte, error) {
	b, err := p.Header.AppendBinary(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func (p *SendMsgNackPacket) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(make([]byte, 0, IpcHeaderSize))
}

func (p *SendMsgNackPacket) UnmarshalBinary(b []byte) error {
	buf := b

	if err := p.Header.UnmarshalBinary(buf); err != nil {
		return err
	}

	return nil
} // End - Send Message NACK Packet
