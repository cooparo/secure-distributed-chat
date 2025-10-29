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

func ConnectToServer(address string) (error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
