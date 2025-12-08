package nethandle

import (
	"context"
	"net"
	"time"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func handleMessage(ctx context.Context, conn net.Conn, mgr *session.SessionManager, query *repository.Queries) error {
	msghdrByte := make([]byte, netprotocol.SizeMessageHeader)
	if _, err := conn.Read(msghdrByte); err != nil {
		return err
	}
	logger.Get().Debugf("Nethandle MessageHeader raw read: %#x", msghdrByte)

	msghdr := &netprotocol.MessageHeader{}
	if err := msghdr.UnmarshalBinary(msghdrByte); err != nil {
		return err
	}

	logger.Get().Infof("Got Message from %s with DataLength %d", msghdr.SendIDAddr.Base32(), msghdr.DataLength)

	sess, ok := mgr.Get(msghdr.SendIDAddr.Base32())
	if !ok {
		// TODO: Check if session in database and reconstruct

		return &NoSessionError{PeerAddress: msghdr.SendIDAddr}
	}

	if sess.Ratchet == nil {
		return &errs.IsNilError{SubjectName: "Ratchet"}
	}

	data := make([]byte, msghdr.DataLength)
	if _, err := conn.Read(data); err != nil {
		return err
	}
	logger.Get().Debugf("Message data from %s is: %#x", msghdr.SendIDAddr.Base32(), data)

	msg := &netprotocol.Message{
		Header: msghdr,
		Data:   data,
	}

	plaintext, err := msg.Decrypt(sess.Ratchet)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Message from %s decrypted to %s", msghdr.SendIDAddr.Base32(), plaintext)

	query.AddMessage(ctx, repository.AddMessageParams{
		SenderAddress:   msghdr.SendIDAddr.Base32(),
		ReceiverAddress: mgr.Address.Base32(),
		Time:            time.Now().Unix(),
		Contents:        string(plaintext),
	})

	return nil
}
