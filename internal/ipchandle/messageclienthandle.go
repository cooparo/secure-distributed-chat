package ipchandle

import (
	"context"
	"io"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func handleClientMessageRequest(ctx context.Context, conn net.Conn) error {
	_ = ctx
	numofmsgshdrBytes := make([]byte, ipcprotocol.SizeNumberOfMessages)
	if _, err := io.ReadFull(conn, numofmsgshdrBytes); err != nil {
		return err
	}

	var numofmsgs uint16
	numofmsgs = common.Uint16UnmarshalBinary(numofmsgshdrBytes)

	var responMsgs []ipcprotocol.MessageResponsePacket
	for i := uint16(0); i < uint16(numofmsgs); i++ {
		currntReshdrBytes := make([]byte, ipcprotocol.SizeMessageResponseHeader)
		if _, err := io.ReadFull(conn, currntReshdrBytes); err != nil {
			return err
		}

		var currntReshdr ipcprotocol.MessageResponseHeader
		if err := currntReshdr.UnmarshalBinary(currntReshdrBytes); err != nil {
			return err
		}

		dataBytes := make([]byte, currntReshdr.MessageLength)
		if _, err := io.ReadFull(conn, dataBytes); err != nil {
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
