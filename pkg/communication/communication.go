package communication

import (
	"fmt"
	"net"
)

// Handle the communication on a given connection
func HandleConnection(c net.Conn) {
	defer c.Close()

	buf := make([]byte, 1) // 1KB buffer
	n, err := c.Read(buf)
	if err != nil {
		fmt.Println("read error:", err)
		return
	}

	fmt.Println("received:", string(buf[:n]))

}

