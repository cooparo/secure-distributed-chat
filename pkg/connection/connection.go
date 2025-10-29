package connection

import "net"

func StartServer(bind string, handleConnection func(net.Conn)) (error) {
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConnection(conn)
	}
}
