package ipchandle

import (
	"context"
	"net"
	"sync"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func MessageRequst(ctx context.Context, conn net.Conn, wg *sync.WaitGroup, address identity.IdentityAddress) error {
	mainhdr := ipcprotocol.MainHeader{
		Version:     ipcprotocol.Version(1),
		CommandType: ipcprotocol.CommandTypeMessageRequest,
	}

	reqthdr := ipcprotocol.MessageRequestHeader{
		Address: address,
	}

	mainBytes, err := mainhdr.MarshalBinary()
	if err != nil {
		return err
	}

	reqBytes, err := reqthdr.MarshalBinary()
	if err != nil {
		return err
	}

	pktbuff := make([]byte, 0, ipcprotocol.SizeMainHeader+ipcprotocol.SizeMessageRequestHeader)
	pktbuff = append(pktbuff, mainBytes...)
	pktbuff = append(pktbuff, reqBytes...)

	logger.Get().Info(pktbuff)

	if _, err := conn.Write(pktbuff); err != nil {
		return err
	}

	wg.Add(1)
	go clientIpcListener(ctx, conn, wg)

	return nil
}
