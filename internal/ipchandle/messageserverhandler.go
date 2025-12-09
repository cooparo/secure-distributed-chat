package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

// handleServerSendMessage
// MessageRequestHeader

func handleServerSendMessage(ctx context.Context, conn net.Conn, query *repository.Queries) error {
	sendhdrByte := make([]byte, ipcprotocol.SizeSendMessageHeader)
	if _, err := conn.Read(sendhdrByte); err != nil {
		return err
	}

	var sendmsghdr ipcprotocol.SendMessageHeader
	if err := sendmsghdr.UnmarshalBinary(sendhdrByte); err != nil {
		return err
	}

	logger.Get().Infof("Sending to: %s: Message length is %d", sendmsghdr.PeerAddres.Base32(), sendmsghdr.MessageContentLength)

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

	logger.Get().Info(msgRows)

	// TODO: if len = 0 then return something empty array

	mainHeader := ipcprotocol.MainHeader{
		Version:     ipcprotocol.Version(1),
		CommandType: ipcprotocol.CommandTypeMessageResponse,
	}

	countOfMsg := ipcprotocol.NumberOfMesseges(len(msgRows))

	var buf []byte

	mainBytes, err := mainHeader.MarshalBinary()
	if err != nil {
		return err
	}
	buf = append(buf, mainBytes...)

	countByts, err := countOfMsg.MarshalBinary()
	if err != nil {
		return err
	}
	buf = append(buf, countByts...)

	for _, msgItem := range msgRows {
		reshdr := ipcprotocol.MessageResponseHeader{
			// somtong liek this if we want to decode from sting to
			ReceiverAddress:      identity.IdentityAddress(msgItem.ReceiverAddress).ByAnyDecodeFromBase32(),
			SenderAddress:        identity.IdentityAddress(msgItem.SenderAddress).ByAnyDecodeFromBase32(),
			Timestamp:            ipcprotocol.Timestamp(msgItem.Time),
			MessageContentLength: uint16(len(msgItem.Contents)),
		}

		reshdrBytes, err := reshdr.MarshalBinary()
		if err != nil {
			return err
		}
		buf = append(buf, reshdrBytes...)

		logger.Get().Info(buf)

		data := ipcprotocol.MessageData(msgItem.Contents)
		dataBytes, err := data.MarshalBinary()
		if err != nil {
			return err
		}
		buf = append(buf, dataBytes...)
	}

	_, err = conn.Write(buf)
	if err != nil {
		return err
	}

	return nil
}
