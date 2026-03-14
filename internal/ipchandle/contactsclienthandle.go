package ipchandle

import (
	"context"
	"io"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func handleClientListContactsResponse(ctx context.Context, conn net.Conn) error {
	hdrByte := make([]byte, ipcprotocol.SizeListContactsResponseHeader)
	if _, err := io.ReadFull(conn, hdrByte); err != nil {
		return err
	}

	var hdr ipcprotocol.ListContactsResponseHeader
	if err := hdr.UnmarshalBinary(hdrByte); err != nil {
		return err
	}

	for range hdr.ContactCount {
		addrByte := make([]byte, identity.SizeIdentityAddress)
		if _, err := io.ReadFull(conn, addrByte); err != nil {
			return err
		}
	}

	return nil
}
