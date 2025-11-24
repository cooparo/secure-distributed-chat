package nethandle

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func HandleKeyExchangeRequest(conn net.Conn, mgr *session.SessionManager) error {
	req, err := netprotocol.ReadKeyExchangeRequest(conn)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Key Exchange Request from %s to %s", req.SendIDAddr.String(), req.RecvIDAddr.String())

	if !mgr.Address().Equal(req.RecvIDAddr) {
		logger.Get().Debug("Key Exchange Request is not for us, ignoring...")
		return nil
	}

	ok, err := req.KeyBundle.Verify(req.SendIDAddr)
	if err != nil {
		logger.Get().Errorf("Got error while verifying attached KeyBundle for Identity %s: %s", req.SendIDAddr.String(), err.Error())
		return err
	}

	if !ok {
		logger.Get().Debugf("KeyBundle for Identity %s failed verification", req.SendIDAddr)
		return nil
	}

	// TODO: verify Request

	// TODO: store identity in database

	ephemeralKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	sharedSecret, err := ephemeralKey.ECDH(req.EphemeralKey)
	if err != nil {
		return err
	}

	ratchet, err := doubleratchet.New(sharedSecret, nil)
	if err != nil {
		return err
	}

	sess := session.Session{
		Ratchet:    ratchet,
		SigningKey: req.KeyBundle.SigningKey,
	}

	mgr.Set(req.SendIDAddr, &sess)

	// TODO: Generate Signature
	resp := netprotocol.KeyExchangeResponse{
		SendIDAddr:   req.RecvIDAddr,
		RecvIDAddr:   req.SendIDAddr,
		EphemeralKey: ephemeralKey.PublicKey(),
		RatchetKey:   ratchet.OurKey.PublicKey(),
	}

	resp.Write(conn)

	return nil
}

func HandleKeyExchangeResponse(conn net.Conn, mgr *session.SessionManager) error {
	resp, err := netprotocol.ReadKeyExchangeResponse(conn)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Key Exchange Response from %s to %s", resp.SendIDAddr.String(), resp.RecvIDAddr.String())

	if mgr.Address().Equal(resp.RecvIDAddr) {
		logger.Get().Debugf("Key Exchange Response is not for us, ignoring...")
		return nil
	}

	// TODO: verify signature on response

	sess, ok := mgr.Get(resp.SendIDAddr)

	if !ok {
		logger.Get().Debug("No session found, ignoring...")
		return nil
	}

	if sess.ExchangeKey == nil {
		logger.Get().Debugf("No Key Exchange in process, ignoring...")
		return nil
	}

	sharedSecret, err := sess.ExchangeKey.ECDH(resp.EphemeralKey)
	if err != nil {
		return err
	}

	ratchet, err := doubleratchet.New(sharedSecret, resp.RatchetKey)
	if err != nil {
		return err
	}

	sess.Ratchet = ratchet
	sess.ExchangeKey = nil

	return nil
}
