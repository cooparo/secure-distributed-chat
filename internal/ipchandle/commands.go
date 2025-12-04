package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func HandleCmdMsgReq(ctx context.Context, conn net.Conn, sm *session.SessionManager) error {
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

func HandleCmdMsgResp(ctx context.Context, conn net.Conn, sm *session.SessionManager) error {
	var pkt ipcprotocol.MsgRespPacket

	// FIX: there is no way to know now, how big the message response will be.
	// We know the max size of a msg response, that is
	// IpcMaxMsgSize * max # of messages = 64 KiB ** 2 = 4 GiB
	// However, since I don't wanna pre-allocate 4 GiB each time I need to handle a MsgResp
	// for now I'll use 64 KiB, hence IpcMaxMsgSize
	msgRespBytes := make([]byte, ipcprotocol.IpcMaxMsgSize)

	if _, err := conn.Read(msgRespBytes); err != nil {
		return err
	}

	if err := pkt.UnmarshalBinary(msgRespBytes); err != nil {
		return err
	}

	logger.Get().Infof("Received %d new messages:", len(pkt.MsgPackets))

	// Display messages
	for _, m := range pkt.MsgPackets {
		logger.Get().Infof("- New message from %s: \"%s\"", m.Sender.Base32(), m.Message)
	}

	return nil
}

func HandleCmdSendMsg(ctx context.Context, conn net.Conn, sm *session.SessionManager) error {
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

func HandleCmdSendMsgAck(ctx context.Context, conn net.Conn, sm *session.SessionManager) error {
	logger.Get().Info("Message sent successfully")
	return nil
}

func HandleCmdSendMsgNack(ctx context.Context, conn net.Conn, sm *session.SessionManager) error {
	logger.Get().Error("Failed to send message")
	return nil
}
