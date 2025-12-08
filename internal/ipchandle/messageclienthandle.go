package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func handleClientMessageRqust(ctx context.Context, conn net.Conn) error {
	numofmsgBytes := make([]byte, ipcprotocol.SizeNumberOfMessages)
	if _, err := conn.Read(numofmsgBytes); err != nil {
		return err
	}

	var numofmsg ipcprotocol.NumberOfMesseges
	if err := numofmsg.UnmarshalBinary(numofmsgBytes); err != nil {
		return err
	}

	var packets []ipcprotocol.MessageResponsePacket
	for range numofmsg {
		bufReadBytes := make([]byte, ipcprotocol.SizeMessageResponseHeader)
		if _, err := conn.Read(bufReadBytes); err != nil {
			return err
		}

		var msgreshdr ipcprotocol.MessageResponseHeader
		if err := msgreshdr.UnmarshalBinary(bufReadBytes); err != nil {
			return err
		}

		bufReadBytes = make([]byte, msgreshdr.MessageContentLength)
		if _, err := conn.Read(bufReadBytes); err != nil {
			return err
		}

		packets = append(packets, ipcprotocol.MessageResponsePacket{
			HeaderResponce: msgreshdr,
			Data:           ipcprotocol.MessageData(bufReadBytes),
		})

		logger.Get().Info("the packets is ", packets)
	}

	return nil
}
