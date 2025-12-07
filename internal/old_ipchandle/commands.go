package ipchandle

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func HandleCmdMsgReq(ctx context.Context, conn net.Conn) error {
	// TODO: fetch new messages from DB

	// Mock response
	me, _ := identity.GenerateIdentity()
	sender, _ := identity.GenerateIdentity()

	myAddr, _ := me.Public().Address()
	senderAddr, _ := sender.Public().Address()

	newMsgs := []ipcprotocol.MsgPacket{
		*ipcprotocol.NewMsgPacket(senderAddr, myAddr, ipcprotocol.Message("Hello Alice")),
		*ipcprotocol.NewMsgPacket(senderAddr, myAddr, ipcprotocol.Message("Be secure")),
		*ipcprotocol.NewMsgPacket(senderAddr, myAddr, ipcprotocol.Message("Be private")),
	}

	resp := ipcprotocol.NewMsgRespPacket(newMsgs)

	data, err := resp.MarshalBinary()
	if err != nil {
		logger.Get().Error("Failed to marshal MsgRespPacket: " + err.Error())
		return err
	}

	conn.Write(data)
	return nil
}

func HandleCmdMsgResp(ctx context.Context, conn net.Conn) error {
	// Decode the number of messages
	noMessageBytes := make([]byte, 0, ipcprotocol.IpcHeaderMsgRespPacketSize)
	if _, err := conn.Read(noMessageBytes); err != nil {
		return err
	}
	noMessage := binary.BigEndian.Uint16(noMessageBytes)

	// Decode each message
	var messages []ipcprotocol.MsgPacket
	for i := 0; i < int(noMessage); i++ {
		messageBytes := make([]byte, 0, ipcprotocol.IpcMaxMsgSize+ipcprotocol.IpcMsgPktHeaderSize)

		var msg ipcprotocol.MsgPacket
		if err := msg.UnmarshalBinary(messageBytes); err != nil {
			return err
		}

		messages = append(messages, msg)
	}

	// Display messages
	logger.Get().Infof("New %d messages", len(messages))
	for _, m := range messages {
		logger.Get().Infof("- New message from %s: \"%s\"", m.Sender.Base32(), m.Message)
	}

	return nil
}

func HandleCmdSendMsg(ctx context.Context, conn net.Conn) error {
	var msg ipcprotocol.MsgPacket

	msgBytes := make([]byte, ipcprotocol.IpcMaxMsgSize)

	if _, err := conn.Read(msgBytes); err != nil {
		return err
	}

	if err := msg.UnmarshalBinary(msgBytes); err != nil {
		return err
	}

	// TODO: forward message to internet
	// If successfully send send an SendMsg ACK
	// SendMsg NACK otherwise

	return nil
}

func HandleCmdSendMsgAck(ctx context.Context, conn net.Conn) error {
	logger.Get().Info("Message sent successfully")
	return nil
}

func HandleCmdSendMsgNack(ctx context.Context, conn net.Conn) error {
	logger.Get().Error("Failed to send message")
	return nil
}
