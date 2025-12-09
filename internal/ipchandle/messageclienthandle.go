package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func handleClientMessageResponse(ctx context.Context, conn net.Conn) error {
	msgresp := &ipcprotocol.MessageResponse{}

	msgresphdrByte := make([]byte, ipcprotocol.SizeMessageResponseHeader)
	if _, err := conn.Read(msgresphdrByte); err != nil {
		return err
	}

	msgresphdr := &ipcprotocol.MessageResponseHeader{}
	if err := msgresphdr.UnmarshalBinary(msgresphdrByte); err != nil {
		return err
	}

	msgresp.Header = msgresphdr
	msgresp.Messages = make([]*ipcprotocol.Message, msgresphdr.MessageCount)

	for range msgresphdr.MessageCount {
		msg := &ipcprotocol.Message{}

		msghdrByte := make([]byte, ipcprotocol.SizeMessageHeader)
		if _, err := conn.Read(msgresphdrByte); err != nil {
			return err
		}

		msghdr := &ipcprotocol.MessageHeader{}
		if err := msghdr.UnmarshalBinary(msghdrByte); err != nil {
			return err
		}

		msg.Header = msghdr

		msg.Data = make([]byte, msghdr.MessageLength)
		if _, err := conn.Read(msg.Data); err != nil {
			return err
		}

		msgresp.Messages = append(msgresp.Messages, msg)
	}

	return nil

}
