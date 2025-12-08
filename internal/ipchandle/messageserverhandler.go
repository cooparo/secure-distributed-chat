package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

// MessageRequestHeader
func handleServerMessageRequest(ctx context.Context, conn net.Conn, query *repository.Queries) error {
	logger.Get().Info("WE ARE IN")

	msgreqhdrByte := make([]byte, ipcprotocol.SizeMessageRequestHeader)
	if _, err := conn.Read(msgreqhdrByte); err != nil {
		return err
	}

	logger.Get().Info("are herer")

	var msgreqhdr ipcprotocol.MessageRequestHeader
	if err := msgreqhdr.UnmarshalBinary(msgreqhdrByte); err != nil {
		return err
	}

	msgRows, err := query.GetMessages(ctx, msgreqhdr.Address.Base32())
	if err != nil {
		return err
	}

	// TODO: if len = 0 then return something empty array

	mainHeader := ipcprotocol.MainHeader{
		Version:     ipcprotocol.Version(1),
		CommandType: ipcprotocol.CommandTypeMessageResponse,
	}

	countOfMsg := ipcprotocol.NumberOfMesseges(len(msgRows))

	buf := make([]byte, 0, ipcprotocol.SizeMainHeader+
		ipcprotocol.SizeNumberOfMessages)

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
		pkt := ipcprotocol.MessageResponsePacket{
			HeaderResponce: ipcprotocol.MessageResponseHeader{
				ReceiverAddress:      identity.IdentityAddress(msgItem.ReceiverAddress),
				SenderAddress:        identity.IdentityAddress(msgItem.SenderAddress),
				Timestamp:            ipcprotocol.Timestamp(msgItem.Time),
				MessageContentLength: uint16(len(msgItem.Contents)),
			},
			Data: ipcprotocol.MessageData(msgItem.Contents),
		}

		pktBytes, err := pkt.MarshalBinary()
		if err != nil {
			return err
		}

		logger.Get().Info(pkt)

		buf = append(buf, pktBytes...)
	}

	_, err = conn.Write(buf)
	if err != nil {
		panic(err)
	}

	return nil
}
