package message

import (
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol/message"
)

func HandleMessage(conn net.Conn) error {
	msg, err := message.Read(conn)
	if err != nil {
		return err
	}
	logger.Get().Debugf("Got message: %v", msg)

	// TODO: decrypt and store message

	return nil
}
