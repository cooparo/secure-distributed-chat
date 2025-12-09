package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func handleClientMessageRequest(ctx context.Context, conn net.Conn) error {
	numofmsgshdrBytes := make([]byte, ipcprotocol.SizeNumberOfMessages)
	if _, err := conn.Read(numofmsgshdrBytes); err != nil {
		return err
	}

	var numofmsgs ipcprotocol.NumberOfMesseges
	if err := numofmsgs.UnmarshalBinary(numofmsgshdrBytes); err != nil {
		return err
	}

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

		dataBytes := make([]byte, currntReshdr.MessageContentLength)
		if _, err := conn.Read(dataBytes); err != nil {
			return err
		}

		currntpkt := ipcprotocol.MessageResponsePacket{
			HeaderResponce: currntReshdr,
			Data:           ipcprotocol.MessageData(dataBytes),
		}

		responMsgs = append(responMsgs, currntpkt)
	}

	return nil

}
