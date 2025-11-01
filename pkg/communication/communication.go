package communication

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

// Handle the communication on a given connection
func HandleConnection(c net.Conn) {
	defer c.Close()

	err := handlePacket(c)
	if err != nil {
		// Write the error to stdout and end the function
		io.WriteString(os.Stdout, err.Error())
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
		return fmt.Errorf("Unknown PacketType with id %d\n", header.PacketType)
	}

	// TODO: Check for the version?
	s := fmt.Sprintf("Got packet with version %d and PacketType %s\n", header.Version, name)
	io.WriteString(os.Stdout, s)

	switch header.PacketType {
	case PacketTypeMessage:
		err := handleMessage(c)
		if err != nil {
			return nil
		}
	default:
		return fmt.Errorf("No handle for PacketType %s\n", name)
	}

	return nil
}

func handleMessage(c net.Conn) (error) {
	header := messageHeader{}
	err := binary.Read(c, binary.BigEndian, &header)
	if err != nil {
		return err
	}
	s := fmt.Sprintf("Got message with length %d\n", header.Length)
	io.WriteString(os.Stdout, s)

	buf := make([]byte, header.Length)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	if n != int(header.Length) {
		return fmt.Errorf("Mismatch between reported message length, and actually read length %d != %d",
			n, header.Length)
	}

	s = fmt.Sprintf("Message contents:\n%s\n", string(buf))
	io.WriteString(os.Stdout, s)

	return nil
}
