package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func sendClearChatNack(conn net.Conn) {
	hdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeClearChatNac,
	}
	pkt, _ := hdr.MarshalBinary()
	conn.Write(pkt)
}

func handleServerClearChat(ctx context.Context, conn net.Conn, state *ServerState) error {
	hdrByte := make([]byte, ipcprotocol.SizeAddPeerHeader)
	if _, err := conn.Read(hdrByte); err != nil {
		return err
	}

	var hdr ipcprotocol.AddPeerHeader
	if err := hdr.UnmarshalBinary(hdrByte); err != nil {
		return err
	}

	addrData := make([]byte, hdr.AddressLength)
	if _, err := conn.Read(addrData); err != nil {
		return err
	}

	address := string(addrData)
	logger.Get().Infof("Clear chat request for address: %s", address)

	if err := state.Query.DeleteMessages(ctx, address); err != nil {
		logger.Get().Warnf("Failed to clear chat for %s: %s", address, err.Error())
		sendClearChatNack(conn)
		return nil
	}

	logger.Get().Infof("Chat with %s cleared", address)

	ackHdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeClearChatAck,
	}
	ackPkt, err := ackHdr.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := conn.Write(ackPkt); err != nil {
		return err
	}

	return nil
}
