package nethandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func handleHeartbeat(ctx context.Context, conn net.Conn, mgr *session.SessionManager) error {
	logger.Get().Infof("Got heartbeat from %s", conn.RemoteAddr().String())

	return nil
}
