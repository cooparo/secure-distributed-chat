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
	sreqByte := make([]byte, netprotocol.SizeSignedKeyExchangeRequest)
	if _, err := conn.Read(sreqByte); err != nil {
		return err
	}
	var sreq netprotocol.SignedKeyExchangeRequest
	if err := sreq.UnmarshalBinary(sreqByte); err != nil {
		return err
	}
	req := sreq.Inner

	logger.Get().Infof("Key Exchange Request from %s to %s", req.SendIDAddr.Base32(), req.RecvIDAddr.Base32())

	if !mgr.Address.Equal(req.RecvIDAddr) {
		logger.Get().Debugf("Key Exchange Request is for %s, but we are %s", req.RecvIDAddr.Base32(), mgr.Address.Base32())
		return &InvalidRecvError{
			SubjectName:         "KeyExchangeRequest",
			SubjectActualRecv:   req.RecvIDAddr,
			SubjectExpectedRecv: mgr.Address,
		}
	}

	skb := req.SignedKeyBundle
	kb := skb.Inner

	calcAddress, err := kb.Address()
	if err != nil {
		logger.Get().Errorf("Got error calculating address from Key Bundle: %s", err.Error())
		return err
	}

	if !calcAddress.Equal(req.SendIDAddr) {
		logger.Get().Warnf("Address %s doesn't match the calculated address %s", req.SendIDAddr.Base32(), calcAddress.Base32())
		return &CalcAddrMismatchError{
			SubjectActualAddress:  req.SendIDAddr,
			SubjectExpectedAddess: calcAddress,
		}
	}

	if err := skb.Verify(); err != nil {
		return err
	}

	if err := sreq.Verify(kb.SigningKey); err != nil {
		return err
	}

	// TODO: store identity in database

	ephemeralPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	pkb := mgr.PrivateKeyBundle

	secrets := make([]byte, 0, 64)

	staticSecret, err := pkb.DiffieHellmanPrivateKey.ECDH(kb.DiffieHellmanKey)
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
		KeyBundle: kb,
	}

	mgr.Set(req.SendIDAddr.Base32(), &sess)

	resp := netprotocol.KeyExchangeResponse{
		SendIDAddr:   req.RecvIDAddr,
		RecvIDAddr:   req.SendIDAddr,
		EphemeralKey: ephemeralPrivateKey.PublicKey(),
		RatchetKey:   ratchet.OurKey.PublicKey(),
	}

	sresp, err := resp.Sign(pkb.SigningPrivateKey)
	if err != nil {
		return err
	}

	srespByte, err := sresp.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := conn.Write(srespByte); err != nil {
		return err
	}

	return nil
}

func HandleKeyExchangeResponse(ctx context.Context, conn net.Conn, mgr *session.SessionManager) error {
	srespByte := make([]byte, netprotocol.SizeSignedKeyExchangeResponse)
	if _, err := conn.Read(srespByte); err != nil {
		return err
	}
	var sresp netprotocol.SignedKeyExchangeResponse
	if err := sresp.UnmarshalBinary(srespByte); err != nil {
		return err
	}
	resp := sresp.Inner

	logger.Get().Infof("Key Exchange Response from %s to %s", resp.SendIDAddr.Base32(), resp.RecvIDAddr.Base32())

	if !mgr.Address.Equal(resp.RecvIDAddr) {
		return &InvalidRecvError{
			SubjectName:         "KeyExchangeResponse",
			SubjectActualRecv:   resp.RecvIDAddr,
			SubjectExpectedRecv: mgr.Address,
		}
	}

	sess, ok := mgr.Get(resp.SendIDAddr.Base32())

	if !ok {
		return &NoSessionError{PeerAddress: resp.SendIDAddr}
	}

	if sess.EphemeralExchangeKey == nil {
		return &NoKeyExchangeError{PeerAddress: resp.SendIDAddr}
	}

	kb := sess.KeyBundle

	if err := sresp.Verify(kb.SigningKey); err != nil {
		return err
	}

	pkb := mgr.PrivateKeyBundle

	secrets := make([]byte, 0, 64)

	staticSecret, err := pkb.DiffieHellmanPrivateKey.ECDH(kb.DiffieHellmanKey)
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
