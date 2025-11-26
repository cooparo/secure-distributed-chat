package nethandle

import (
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func HandleHeartbeat(conn net.Conn, mgr *session.SessionManager) error {
	logger.Get().Infof("Got heartbeat from %s", conn.RemoteAddr().String())

	return nil
}
