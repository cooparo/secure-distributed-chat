package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func handleClientMessageRequest(ctx context.Context, conn net.Conn) error {
	numofmsgshdrBytes := make([]byte, ipcprotocol.SizeNumberOfMessages)
	if _, err := conn.Read(numofmsgshdrBytes); err != nil {
		return err
	}

	var numofmsgs uint16
	numofmsgs = common.Uint16UnmarshalBinary(numofmsgshdrBytes)

	var responMsgs []ipcprotocol.MessageResponsePacket
	for range numofmsgs {
		currntReshdrBytes := make([]byte, ipcprotocol.SizeMessageResponseHeader)
		if _, err := conn.Read(currntReshdrBytes); err != nil {
			return err
		}

		var currntReshdr ipcprotocol.MessageResponseHeader
		if err := currntReshdr.UnmarshalBinary(currntReshdrBytes); err != nil {
			return err
		}

		dataBytes := make([]byte, currntReshdr.MessageLength)
		if _, err := conn.Read(dataBytes); err != nil {
			return err
		}

		currntpkt := ipcprotocol.MessageResponsePacket{
			Header: currntReshdr,
			Data:   ipcprotocol.MessageData(dataBytes),
		}

		responMsgs = append(responMsgs, currntpkt)
	}

	return nil

}
