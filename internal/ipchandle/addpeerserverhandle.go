package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/internal/netclient"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func sendAddPeerNack(conn net.Conn) {
	hdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeAddPeerNac,
	}
	pkt, _ := hdr.MarshalBinary()
	conn.Write(pkt)
}

func handleServerAddPeer(ctx context.Context, conn net.Conn, state *ServerState) error {
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

	host := string(addrData)
	logger.Get().Infof("Add peer request for host: %s", host)

	ourAddress, err := state.PrivKeyBundle.Public().Address()
	if err != nil {
		logger.Get().Warnf("Failed to get our address: %s", err.Error())
		sendAddPeerNack(conn)
		return nil
	}

	err = netclient.DiscoverPeer(
		ctx,
		host,
		ourAddress,
		state.OurSignedKeyBundle,
		state.OurSignedNetworkUpdate,
		state.Query,
	)
	if err != nil {
		logger.Get().Warnf("Discovery failed for %s: %s", host, err.Error())
		sendAddPeerNack(conn)
		return nil
	}

	ackHdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeAddPeerAck,
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
