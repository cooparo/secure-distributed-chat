package ipc

import (
	"fmt"
)

const maxCmdPayloadSize = ^uint16(0) // 64 KiB

type Cmd uint8

const (
	CmdMsgReq Cmd = iota
	CmdMsgResp
	CmdSendMsg
	CmdSendMsgAck
)

var CmdTypeName = map[Cmd]string{
	CmdMsgReq:     "message request",
	CmdMsgResp:    "message response",
	CmdSendMsg:    "send message",
	CmdSendMsgAck: "send message ack",
}

type MsgRespPacket struct {
	header     Header
	msgPackets []MsgPacket
}

func NewMsgRespPacket(messages []MsgPacket) *MsgRespPacket {
	h := NewHeader(CmdMsgResp)

	return &MsgRespPacket{
		header:     *h,
		msgPackets: messages,
	}
}

func (p *MsgRespPacket) MarshalBinary() ([]byte, error) {

	// Serialize all messages
	var payload []byte
	for _, msgPacket := range p.msgPackets {
		msgPacketBytes, err := msgPacket.MarshalBinary()

		if err != nil {
			return nil, err
		}

		payload = append(payload, msgPacketBytes...)
	}

	// Set header length
	if len(payload) > int(maxCmdPayloadSize) {
		return nil, fmt.Errorf("ipc msg resp packet: payload too large")
	}
	p.header.cmdPayloadLenght = uint16(len(payload))

	headerBytes, err := p.header.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ipc msg resp packet: %w", err)
	}

	return append(headerBytes, payload...), nil
}

func (p *MsgRespPacket) UnmarshalBinary(b []byte) error {
	if len(b) < headerSize {
		return fmt.Errorf("ipc msg resp packet: buffer too short for header")
	}

	if err := p.header.UnmarshalBinary(b); err != nil {
		return err
	}

	// fmt.Printf("[Header] cmdPayloadLenght: %d\n", p.header.cmdPayloadLenght)
	remainingBytes := int(p.header.cmdPayloadLenght)

	if len(b) < headerSize+remainingBytes {
		return fmt.Errorf("ipc msg resp packet: buffer too short (expected %d, got %d)", headerSize+remainingBytes, len(b))
	}

	offset := headerSize
	p.msgPackets = nil

	for remainingBytes > 0 {
		t := MsgPacket{}

		var err error
		readBytes, err := t.UnmarshalBinary(b[offset:])

		if err != nil {
			return err
		}

		// Safety check for infinite loop (if bytesRead is 0)
		if readBytes == 0 {
			return fmt.Errorf("ipc msg resp packet: read 0 bytes, stuck in loop")
		}

		// Safety check for underflow
		if int(readBytes) > remainingBytes {
			return fmt.Errorf("ipc msg resp packet: message length exceeds packet bounds")
		}

		p.msgPackets = append(p.msgPackets, t)

		offset += int(readBytes)
		remainingBytes -= int(readBytes)
	}

	return nil
}

type MsgReqPacket struct {
	header Header
}

func NewMsgReqPacket() *MsgReqPacket {
	h := NewHeader(CmdMsgReq)

	return &MsgReqPacket{
		header: *h,
	}
}

func (p *MsgReqPacket) MarshalBinary() ([]byte, error) {
	buf, err := p.header.MarshalBinary()

	if err != nil {
		return nil, err
	}

	return buf, nil
}

func (p *MsgReqPacket) UnmarshalBinary(b []byte) error {
	p.header.UnmarshalBinary(b)
	return nil
}

type SendMsgAckPacket struct {
	header Header
}

func NewSendMsgAckPacket() *SendMsgAckPacket {
	h := NewHeader(CmdSendMsgAck)

	return &SendMsgAckPacket{
		header: *h,
	}
}

func (p *SendMsgAckPacket) MarshalBinary() ([]byte, error) {
	buf, err := p.header.MarshalBinary()

	if err != nil {
		return nil, err
	}

	return buf, nil
}

func (p *SendMsgAckPacket) UnmarshalBinary(b []byte) error {
	p.header.UnmarshalBinary(b)
	return nil
}

type SendMsgPacket struct {
	header    Header
	msgPacket MsgPacket
}

func NewSendMsgPacket(p MsgPacket) *SendMsgPacket {
	h := NewHeader(CmdSendMsg)

	return &SendMsgPacket{
		header:    *h,
		msgPacket: p,
	}
}

func (p *SendMsgPacket) MarshalBinary() ([]byte, error) {
	msgPacketBytes, err := p.msgPacket.MarshalBinary()

	if err != nil {
		return nil, err
	}

	p.header.cmdPayloadLenght = uint16(len(msgPacketBytes))

	if p.header.cmdPayloadLenght > maxMsgPktSize {
		return nil, fmt.Errorf("ipc msg send packet: payload too large")
	}

	headerBytes, err := p.header.MarshalBinary()

	if err != nil {
		return nil, err
	}

	return append(headerBytes, msgPacketBytes...), nil
}

func (p *SendMsgPacket) UnmarshalBinary(b []byte) error {
	if err := p.header.UnmarshalBinary(b); err != nil {
		return err
	}

	if _, err := p.msgPacket.UnmarshalBinary(b[headerSize:]); err != nil {
		return err
	}

	return nil
}
