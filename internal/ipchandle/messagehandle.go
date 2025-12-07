package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
)

func handleMessageRqust(ctx context.Context, conn net.Conn, query *repository.Queries) error {
	logger.Get().Infof("Got heartbeat from %s", conn.RemoteAddr().String())

	return nil
}
