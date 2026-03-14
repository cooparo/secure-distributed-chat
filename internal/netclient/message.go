package netclient

import (
	"fmt"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func SendMessage(conn net.Conn, mgr *session.SessionManager, peerAddr identity.IdentityAddress, plaintext []byte) error {
	sess, ok := mgr.Get(peerAddr.Base32())
	if !ok {
		return fmt.Errorf("no session for peer %s", peerAddr.Base32())
	}

	msg, err := netprotocol.MakeMessage(mgr.Address, sess.Ratchet, plaintext)
	if err != nil {
		return fmt.Errorf("make message: %w", err)
	}

	mainhdr := &netprotocol.MainHeader{
		Version:    1,
		PacketType: netprotocol.PacketTypeMessage,
	}

	pkt, err := mainhdr.MarshalBinary()
	if err != nil {
		return err
	}

	pkt, err = msg.AppendBinary(pkt)
	if err != nil {
		return err
	}

	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	return nil
}
