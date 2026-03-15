package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func sendRemovePeerNack(conn net.Conn) {
	hdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeRemovePeerNac,
	}
	pkt, _ := hdr.MarshalBinary()
	conn.Write(pkt)
}

func handleServerRemovePeer(ctx context.Context, conn net.Conn, state *ServerState) error {
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
	logger.Get().Infof("Remove peer request for address: %s", address)

	if err := state.Query.DeleteIdentity(ctx, address); err != nil {
		logger.Get().Warnf("Failed to delete identity %s: %s", address, err.Error())
		sendRemovePeerNack(conn)
		return nil
	}

	state.Mgr.Delete(address)

	logger.Get().Infof("Peer %s removed", address)

	ackHdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeRemovePeerAck,
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
