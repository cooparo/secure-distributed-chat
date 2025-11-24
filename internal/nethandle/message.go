package nethandle

import (
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func HandleMessage(conn net.Conn, mgr *session.SessionManager) error {
	msg, err := netprotocol.ReadMessage(conn)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Got message: %v", msg)

	// TODO: decrypt and store message

	return nil
}
