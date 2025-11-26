package nethandle

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func HandleKeyExchangeRequest(ctx context.Context, conn net.Conn, mgr *session.SessionManager) error {
	reqByte := make([]byte, netprotocol.SizeKeyExchangeRequest)
	if _, err := conn.Read(reqByte); err != nil {
		return err
	}
	var req netprotocol.KeyExchangeRequest
	if err := req.UnmarshalBinary(reqByte); err != nil {
		return err
	}

	logger.Get().Infof("Key Exchange Request from %s to %s", req.SendIDAddr.Base32(), req.RecvIDAddr.Base32())

	if !mgr.Address.Equal(req.RecvIDAddr) {
		logger.Get().Debugf("Key Exchange Request is for %s, but we are %s", req.RecvIDAddr.Base32(), mgr.Address.Base32())
		return &InvalidRecvErr{
			SubjectName:         "KeyExchangeRequest",
			SubjectActualRecv:   req.RecvIDAddr,
			SubjectExpectedRecv: mgr.Address,
		}
	}

	calcAddress, err := req.SignedKeyBundle.KeyBundle.Address()
	if err != nil {
		logger.Get().Errorf("Got error calculating address from KeyBundle: %s", err.Error())
		return err
	}

	if !calcAddress.Equal(req.SendIDAddr) {
		logger.Get().Warnf("Address %s doesn't match the calculated address %s", req.SendIDAddr.Base32(), calcAddress.Base32())
		return &CalcAddrMismatchError{
			SubjectActualAddress:  req.SendIDAddr,
			SubjectExpectedAddess: calcAddress,
		}
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

	secrets := make([]byte, 0, 64)

	staticSecret, err := mgr.PrivateKeyBundle.DiffieHellmanPrivateKey.ECDH(req.SignedKeyBundle.KeyBundle.DiffieHellmanKey)
	if err != nil {
		return err
	}
	secrets = append(secrets, staticSecret...)

	ephemeralSecret, err := ephemeralPrivateKey.ECDH(req.EphemeralKey)
	if err != nil {
		return err
	}
	secrets = append(secrets, ephemeralSecret...)

	sharedSecret := sha3.Sum256(secrets)

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

	respByte, err := resp.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := conn.Write(respByte); err != nil {
		return err
	}

	return nil
}

func HandleKeyExchangeResponse(ctx context.Context, conn net.Conn, mgr *session.SessionManager) error {
	respByte := make([]byte, netprotocol.SizeKeyExchangeResponse)
	if _, err := conn.Read(respByte); err != nil {
		return err
	}
	var resp netprotocol.KeyExchangeResponse
	if err := resp.UnmarshalBinary(respByte); err != nil {
		return err
	}

	logger.Get().Infof("Key Exchange Response from %s to %s", resp.SendIDAddr.Base32(), resp.RecvIDAddr.Base32())

	if !mgr.Address.Equal(resp.RecvIDAddr) {
		logger.Get().Warnf("Key Exchange Response is for %s, but we are %s", resp.RecvIDAddr.Base32(), mgr.Address.Base32())
		return &InvalidRecvErr{
			SubjectName:         "KeyExchangeResponse",
			SubjectActualRecv:   resp.RecvIDAddr,
			SubjectExpectedRecv: mgr.Address,
		}
	}

	sess, ok := mgr.Get(resp.SendIDAddr.Base32())

	if !ok {
		logger.Get().Debug("No session found, ignoring...")
		return nil
	}

	if sess.EphemeralExchangeKey == nil {
		logger.Get().Debugf("No Key Exchange in process, ignoring...")
		return nil
	}

	// TODO: verify signature on response

	secrets := make([]byte, 0, 64)

	staticSecret, err := mgr.PrivateKeyBundle.DiffieHellmanPrivateKey.ECDH(sess.KeyBundle.DiffieHellmanKey)
	if err != nil {
		return err
	}
	secrets = append(secrets, staticSecret...)

	ephemeralSecret, err := sess.EphemeralExchangeKey.ECDH(resp.EphemeralKey)
	if err != nil {
		return err
	}
	secrets = append(secrets, ephemeralSecret...)

	sharedSecret := sha3.Sum256(secrets)

	ratchet, err := doubleratchet.New(sharedSecret[:], resp.RatchetKey)
	if err != nil {
		return err
	}

	sess.Ratchet = ratchet
	sess.EphemeralExchangeKey = nil

	return nil
}
