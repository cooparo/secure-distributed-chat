package nethandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func handleMessage(ctx context.Context, conn net.Conn, mgr *session.SessionManager) error {
	mhByte := make([]byte, netprotocol.SizeMessageHeader)
	if _, err := conn.Read(mhByte); err != nil {
		return err
	}
	var mh netprotocol.MessageHeader
	if err := mh.UnmarshalBinary(mhByte); err != nil {
		return err
	}

	logger.Get().Infof("Got Message from %s with DataLength %d", mh.IdentityAddress.Base32(), mh.DataLength)

	sess, ok := mgr.Get(mh.IdentityAddress.Base32())
	if !ok {
		// TODO: Check if session in database
		return &NoSessionError{PeerAddress: mh.IdentityAddress}
	}

	if sess.Ratchet == nil {
		return &errs.IsNilError{SubjectName: "Ratchet"}
	}

	data := make([]byte, mh.DataLength)
	if _, err := conn.Read(data); err != nil {
		return err
	}

	logger.Get().Debugf("Message data from %s is: %#x", mh.IdentityAddress.Base32(), data)

	plaintext, err := sess.Ratchet.Decrypt(mh.RatchetKey, data, mhByte)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Message from %s decrypted to %s", mh.IdentityAddress.Base32(), plaintext)

	// TODO: store message

	return nil
}
