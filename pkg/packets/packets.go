package packets

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/messageprotocol"
)

type PacketType uint8

const (
	PacketTypeMessage PacketType = iota
)

var packetTypeName = map[PacketType]string{
	PacketTypeMessage: "message",
}

type mainHeader struct {
	Version    uint8
	PacketType PacketType
}

// Handle the communication on a given connection
func HandleConnection(c net.Conn) {
	defer c.Close()

	err := handlePacket(c)
	if err != nil {
		// Write the error to stderr and end the function
		logger.Get().Error(err.Error())
		return
	}
}

// Handle a incoming packet
func handlePacket(c net.Conn) (error) {
	header := mainHeader{}
	err := binary.Read(c, binary.BigEndian, &header)
	if err != nil {
		return err
	}
	name, ok := packetTypeName[header.PacketType]
	if !ok {
		return fmt.Errorf("Unknown PacketType with id %d", header.PacketType)
	}

	// TODO: Check for the version?
	s := fmt.Sprintf("Got packet with version %d and PacketType %s (%#x)", header.Version, name, header.PacketType)
	logger.Get().Debug(s)

	switch header.PacketType {
	case PacketTypeMessage:
		err := messageprotocol.HandleMessage(c)
		if err != nil {
			return nil
		}
	default:
		return fmt.Errorf("No handle for PacketType %s", name)
	}

	return nil
}
