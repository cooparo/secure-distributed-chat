package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func handleServerSendMessage(ctx context.Context, conn net.Conn, query *repository.Queries) error {

	sendmsghdrByte := make([]byte, ipcprotocol.SizeSendMessageHeader)
	if _, err := conn.Read(sendmsghdrByte); err != nil {
		return err
	}

	sendmsghdr := &ipcprotocol.SendMessageHeader{}
	if err := sendmsghdr.UnmarshalBinary(sendmsghdrByte); err != nil {
		return err
	}

	logger.Get().Infof("Sending to: %s", sendmsghdr.PeerAddress.Base32())

	msg := &ipcprotocol.Message{}

	msghdrByte := make([]byte, ipcprotocol.SizeMessageHeader)
	if _, err := conn.Read(msghdrByte); err != nil {
		return err
	}

	msghdr := &ipcprotocol.MessageHeader{}
	if err := msghdr.UnmarshalBinary(msghdrByte); err != nil {
		return err
	}

	msg.Header = msghdr

	logger.Get().Infof("Message Length: %d", msghdr.MessageLength)

	msgData := make([]byte, msghdr.MessageLength)
	if _, err := conn.Read(msgData); err != nil {
		return err
	}

	logger.Get().Debugf("Message data: %s", msgData)

	msg.Data = msgData

	return nil
}

func handleServerMessageRequest(ctx context.Context, conn net.Conn, query *repository.Queries) error {
	msgreqhdrByte := make([]byte, ipcprotocol.SizeMessageRequestHeader)
	if _, err := conn.Read(msgreqhdrByte); err != nil {
		return err
	}

	var msgreqhdr ipcprotocol.MessageRequestHeader
	if err := msgreqhdr.UnmarshalBinary(msgreqhdrByte); err != nil {
		return err
	}

	msgRows, err := query.GetMessages(ctx, msgreqhdr.Address.Base32())
	if err != nil {
		return err
	}

	// TODO: if len = 0 then return something empty array

	mainhdr := &ipcprotocol.MainHeader{
		Version:     ipcprotocol.Version(1),
		CommandType: ipcprotocol.CommandTypeMessageResponse,
	}

	pkt, err := mainhdr.MarshalBinary()
	if err != nil {
		return err
	}

	msgresphdr := &ipcprotocol.MessageResponseHeader{
		MessageCount: uint16(len(msgRows)),
	}

	pkt, err = msgresphdr.AppendBinary(pkt)
	if err != nil {
		return err
	}

	for _, msgItem := range msgRows {
		senderAddress, err := identity.IdentityFromBase32(msgItem.SenderAddress)
		if err != nil {
			return err
		}
		receiverAddress, err := identity.IdentityFromBase32(msgItem.ReceiverAddress)
		if err != nil {
			return err
		}

		msgData := []byte(msgItem.Contents)

		msghdr := &ipcprotocol.MessageHeader{
			SenderAddress:   senderAddress,
			ReceiverAddress: receiverAddress,
			Timestamp:       common.Timestamp(msgItem.Time),
			MessageLength:   uint16(len(msgData)),
		}

		msg := &ipcprotocol.Message{
			Header: msghdr,
			Data:   msgData,
		}

		pkt, err = msg.AppendBinary(pkt)
		if err != nil {
			return err
		}
	}

	if _, err := conn.Write(pkt); err != nil {
		return err
	}

	return nil
}
