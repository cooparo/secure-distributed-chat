package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func handleServerListContacts(ctx context.Context, conn net.Conn, state *ServerState) error {
	addresses, err := state.Query.GetAllIdentities(ctx)
	if err != nil {
		logger.Get().Warnf("Failed to get identities: %s", err.Error())
		addresses = []string{}
	}

	mainhdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeListContactsResponse,
	}

	pkt, err := mainhdr.MarshalBinary()
	if err != nil {
		return err
	}

	var idAddrs []identity.IdentityAddress
	for _, addrStr := range addresses {
		addr, err := identity.IdentityFromBase32(addrStr)
		if err != nil {
			logger.Get().Warnf("Skipping invalid address %s: %s", addrStr, err.Error())
			continue
		}
		idAddrs = append(idAddrs, addr)
	}

	resp := &ipcprotocol.ListContactsResponse{
		Header: &ipcprotocol.ListContactsResponseHeader{
			ContactCount: uint16(len(idAddrs)),
		},
		Addresses: idAddrs,
	}

	pkt, err = resp.AppendBinary(pkt)
	if err != nil {
		return err
	}

	if _, err := conn.Write(pkt); err != nil {
		return err
	}

	return nil
}
