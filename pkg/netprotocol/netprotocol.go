package netprotocol

import (
	"encoding/binary"
	"io"
)

type PacketType uint8

const (
	PacketTypeHeartbeat PacketType = iota
	PacketTypeMessage
	PacketTypeKeyExchangeRequest
	PacketTypeKeyExchangeResponse
)

type MainHeader struct {
	Version    uint8
	PacketType PacketType
}

func (h *MainHeader) Write(w io.Writer) error {
	err := binary.Write(w, binary.BigEndian, h)
	if err != nil {
		return err
	}

	return nil
}

func Read(r io.Reader) (*MainHeader, error) {
	h := MainHeader{}
	err := binary.Read(r, binary.BigEndian, &h)
	if err != nil {
		return nil, err
	}

	return &h, nil
}
