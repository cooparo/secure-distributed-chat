package communication

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Handle the communication on a given connection
func HandleConnection(c net.Conn) {
	defer c.Close()

	handlePacket(c)
}

func handlePacket(c net.Conn) error {
	mh := mainHeader{}
	err := binary.Read(c, binary.BigEndian, &mh)
	if err != nil {
		return err
	}
	fmt.Println(mh)
	return nil
}
