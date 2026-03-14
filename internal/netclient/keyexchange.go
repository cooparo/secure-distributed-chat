package netclient

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"io"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func InitiateKeyExchange(
	conn net.Conn,
	mgr *session.SessionManager,
	peerAddr identity.IdentityAddress,
	peerKeyBundle *identity.KeyBundle,
	ourSignedKeyBundle *identity.SignedKeyBundle,
	ourSignedNetworkUpdate *identity.SignedNetworkUpdate,
) error {
	ephemeralPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}

	privkeybndl := mgr.PrivateKeyBundle

	kexreq := &netprotocol.KeyExchangeRequest{
		SendIDAddr:          mgr.Address,
		RecvIDAddr:          peerAddr,
		SignedKeyBundle:     ourSignedKeyBundle,
		SignedNetworkUpdate: ourSignedNetworkUpdate,
		EphemeralKey:        ephemeralPrivateKey.PublicKey(),
	}

	sigkexreq, err := kexreq.Sign(privkeybndl.SigningPrivateKey)
	if err != nil {
		return fmt.Errorf("sign key exchange request: %w", err)
	}

	mainhdr := &netprotocol.MainHeader{
		Version:    1,
		PacketType: netprotocol.PacketTypeKeyExchangeRequest,
	}

	pkt, err := mainhdr.MarshalBinary()
	if err != nil {
		return err
	}

	pkt, err = sigkexreq.AppendBinary(pkt)
	if err != nil {
		return err
	}

	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("send key exchange request: %w", err)
	}

	logger.Get().Infof("Sent KeyExchangeRequest to %s", peerAddr.Base32())

	// Read response: MainHeader + SignedKeyExchangeResponse
	respMainhdrByte := make([]byte, netprotocol.SizeMainHeader)
	if _, err := io.ReadFull(conn, respMainhdrByte); err != nil {
		return fmt.Errorf("read key exchange response header: %w", err)
	}

	respMainhdr := &netprotocol.MainHeader{}
	if err := respMainhdr.UnmarshalBinary(respMainhdrByte); err != nil {
		return err
	}

	if respMainhdr.PacketType != netprotocol.PacketTypeKeyExchangeResponse {
		return fmt.Errorf("expected KeyExchangeResponse, got packet type %d", respMainhdr.PacketType)
	}

	sigkexrespByte := make([]byte, netprotocol.SizeSignedKeyExchangeResponse)
	if _, err := io.ReadFull(conn, sigkexrespByte); err != nil {
		return fmt.Errorf("read key exchange response: %w", err)
	}

	sigkexresp := &netprotocol.SignedKeyExchangeResponse{}
	if err := sigkexresp.UnmarshalBinary(sigkexrespByte); err != nil {
		return err
	}
	kexresp := sigkexresp.Inner

	if err := sigkexresp.Verify(peerKeyBundle.SigningKey); err != nil {
		return fmt.Errorf("verify key exchange response: %w", err)
	}

	// Compute shared secret (mirrors responder logic)
	secrets := make([]byte, 0, 64)

	// Static-static DH
	staticSecret, err := privkeybndl.DiffieHellmanPrivateKey.ECDH(peerKeyBundle.DiffieHellmanKey)
	if err != nil {
		return fmt.Errorf("static ECDH: %w", err)
	}
	secrets = append(secrets, staticSecret...)

	// Ephemeral-ephemeral DH
	ephemeralSecret, err := ephemeralPrivateKey.ECDH(kexresp.EphemeralKey)
	if err != nil {
		return fmt.Errorf("ephemeral ECDH: %w", err)
	}
	secrets = append(secrets, ephemeralSecret...)

	sharedSecret := sha3.Sum256(secrets)

	ratchet, err := doubleratchet.New(sharedSecret[:], kexresp.RatchetKey)
	if err != nil {
		return fmt.Errorf("init double ratchet: %w", err)
	}

	sess := &session.Session{
		Ratchet:   ratchet,
		KeyBundle: peerKeyBundle,
	}

	mgr.Set(peerAddr.Base32(), sess)

	logger.Get().Infof("Key exchange completed with %s", peerAddr.Base32())

	return nil
}
