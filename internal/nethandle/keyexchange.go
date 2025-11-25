package nethandle

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

// TODO: Return more errors to the callers

func HandleKeyExchangeRequest(conn net.Conn, mgr *session.SessionManager) error {
	req, err := netprotocol.ReadKeyExchangeRequest(conn)
	if err != nil {
		return err
	}

	logger.Get().Debugf("Key Exchange Request from %s to %s", req.SendIDAddr.Base32(), req.RecvIDAddr.Base32())

	if !mgr.Address.Equal(req.RecvIDAddr) {
		logger.Get().Debug("Key Exchange Request is not for us, ignoring...")
		return nil
	}

	calcAddress, err := req.SignedKeyBundle.KeyBundle.Address()
	if err != nil {
		logger.Get().Errorf("Got error calculating address from KeyBundle: %s", err.Error())
		return err
	}

	if !calcAddress.Equal(req.SendIDAddr) {
		logger.Get().Warnf("Address %s doesn't match the calculated address %s", req.SendIDAddr.Base32(), calcAddress.Base32())
		return nil
	}

	if !req.SignedKeyBundle.Verify() {
		logger.Get().Warn("KeyBundle failed verification")
		return nil
	}

	// TODO: verify Request

	// TODO: store identity in database

	ephemeralPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	staticSecret, err := mgr.PrivateKeyBundle.DiffieHellmanPrivateKey.ECDH(req.SignedKeyBundle.KeyBundle.DiffieHellmanKey)
	if err != nil {
		return err
	}

	ephemeralSecret, err := ephemeralPrivateKey.ECDH(req.EphemeralKey)
	if err != nil {
		return err
	}

	sharedSecret := sha3.Sum256(append(staticSecret, ephemeralSecret...))

	ratchet, err := doubleratchet.New(sharedSecret[:], nil)
	if err != nil {
		return err
	}

	sess := session.Session{
		Ratchet:   ratchet,
		KeyBundle: req.SignedKeyBundle.KeyBundle,
	}

	mgr.Set(req.SendIDAddr.Base32(), &sess)

	// TODO: Generate Signature
	resp := netprotocol.KeyExchangeResponse{
		SendIDAddr:   req.RecvIDAddr,
		RecvIDAddr:   req.SendIDAddr,
		EphemeralKey: ephemeralPrivateKey.PublicKey(),
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

	logger.Get().Debugf("Key Exchange Response from %s to %s", resp.SendIDAddr.Base32(), resp.RecvIDAddr.Base32())

	if mgr.Address.Equal(resp.RecvIDAddr) {
		logger.Get().Debugf("Key Exchange Response is not for us, ignoring...")
		return nil
	}

	// TODO: verify signature on response

	sess, ok := mgr.Get(resp.SendIDAddr.Base32())

	if !ok {
		logger.Get().Debug("No session found, ignoring...")
		return nil
	}

	if sess.EphemeralExchangeKey == nil {
		logger.Get().Debugf("No Key Exchange in process, ignoring...")
		return nil
	}

	staticSecret, err := mgr.PrivateKeyBundle.DiffieHellmanPrivateKey.ECDH(sess.KeyBundle.DiffieHellmanKey)

	ephemeralSecret, err := sess.EphemeralExchangeKey.ECDH(resp.EphemeralKey)
	if err != nil {
		return err
	}

	sharedSecret := sha3.Sum256(append(staticSecret, ephemeralSecret...))

	ratchet, err := doubleratchet.New(sharedSecret[:], resp.RatchetKey)
	if err != nil {
		return err
	}

	sess.Ratchet = ratchet
	sess.EphemeralExchangeKey = nil

	return nil
}
