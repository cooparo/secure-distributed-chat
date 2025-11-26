package nethandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func HandleMessage(ctx context.Context, conn net.Conn, mgr *session.SessionManager) error {
	mhByte := make([]byte, netprotocol.SizeMessageHeader)
	if _, err := conn.Read(mhByte); err != nil {
		return err
	}
	var mh netprotocol.MessageHeader
	if err := mh.UnmarshalBinary(mhByte); err != nil {
		return err
	}

	logger.Get().Infof("Got Message from %s with DataLength %d", mh.IdentityAddress.Base32(), mh.DataLength)

	data := make([]byte, mh.DataLength)
	if _, err := conn.Read(data); err != nil {
		return err
	}

	logger.Get().Debugf("Message data from %s is: %#x", mh.IdentityAddress.Base32(), data)

	_ = netprotocol.Message{
		Header: &mh,
		Data:   data,
	}

	// TODO: decrypt

	// TODO: store message

	return nil
}
