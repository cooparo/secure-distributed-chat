package communication

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
)

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
	s := fmt.Sprintf("Got packet with version %d and PacketType %s", header.Version, name)
	logger.Get().Debug(s)

	switch header.PacketType {
	case PacketTypeMessage:
		err := handleMessage(c)
		if err != nil {
			return nil
		}
	default:
		return fmt.Errorf("No handle for PacketType %s", name)
	}

	return nil
}

func handleMessage(c net.Conn) (error) {
	header := messageHeader{}
	err := binary.Read(c, binary.BigEndian, &header)
	if err != nil {
		return err
	}

	s := fmt.Sprintf("Got message with length %d", header.Length)
	logger.Get().Debug(s)

	buf := make([]byte, header.Length)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if n != int(header.Length) {
		return fmt.Errorf("Mismatch between reported message length, and actually read length %d != %d",
			n, header.Length)
	}

	s = fmt.Sprintf("Message contents: %s", string(buf))
	logger.Get().Debug(s)

	return nil
}
