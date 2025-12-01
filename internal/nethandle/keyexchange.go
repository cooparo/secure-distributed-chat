package nethandle

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base64"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/doubleratchet"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func handleKeyExchangeRequest(ctx context.Context, conn net.Conn, mgr *session.SessionManager, query *repository.Queries) error {
	sigkexreqByte := make([]byte, netprotocol.SizeSignedKeyExchangeRequest)
	if _, err := conn.Read(sigkexreqByte); err != nil {
		return err
	}
	var sigkexreq netprotocol.SignedKeyExchangeRequest
	if err := sigkexreq.UnmarshalBinary(sigkexreqByte); err != nil {
		return err
	}
	kexreq := sigkexreq.Inner

	logger.Get().Infof("Key Exchange Request from %s to %s", kexreq.SendIDAddr.Base32(), kexreq.RecvIDAddr.Base32())

	if !mgr.Address.Equal(kexreq.RecvIDAddr) {
		logger.Get().Debugf("Key Exchange Request is for %s, but we are %s", kexreq.RecvIDAddr.Base32(), mgr.Address.Base32())
		return &InvalidRecvError{
			SubjectName:         "KeyExchangeRequest",
			SubjectActualRecv:   kexreq.RecvIDAddr,
			SubjectExpectedRecv: mgr.Address,
		}
	}

	sigkeybndl := kexreq.SignedKeyBundle
	keybndl := sigkeybndl.Inner

	calcAddress, err := keybndl.Address()
	if err != nil {
		logger.Get().Errorf("Got error calculating address from Key Bundle: %s", err.Error())
		return err
	}

	if !calcAddress.Equal(kexreq.SendIDAddr) {
		logger.Get().Warnf("Address %s doesn't match the calculated address %s", kexreq.SendIDAddr.Base32(), calcAddress.Base32())
		return &CalcAddrMismatchError{
			SubjectActualAddress:  kexreq.SendIDAddr,
			SubjectExpectedAddess: calcAddress,
		}
	}

	if err := sigkeybndl.Verify(); err != nil {
		return err
	}

	signetupd := kexreq.SignedNetAddressUpdate
	netupd := signetupd.Inner

	if err := signetupd.Verify(keybndl.SigningKey); err != nil {
		return err
	}

	if err := sigkexreq.Verify(keybndl.SigningKey); err != nil {
		return err
	}

	encoding := base64.StdEncoding

	sigkeybndlByte, err := sigkeybndl.MarshalBinary()
	if err != nil {
		return err
	}
	sigkeybndlEncoded := make([]byte, encoding.EncodedLen(len(sigkeybndlByte)))
	encoding.Encode(sigkeybndlEncoded, sigkeybndlByte)

	signetupdByte, err := signetupd.MarshalBinary()
	if err != nil {
		return err
	}
	signetupdEncoded := make([]byte, encoding.EncodedLen(len(signetupdByte)))
	encoding.Encode(signetupdEncoded, signetupdByte)

	query.AddIdentity(ctx, repository.AddIdentityParams{
		Address:           kexreq.SendIDAddr.Base32(),
		KeyBundle:         string(sigkeybndlEncoded),
		NetAddrBundleTime: int64(netupd.Timestamp),
		NetAddrBundle:     string(signetupdEncoded),
	})

	ephemeralPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	privkeybndl := mgr.PrivateKeyBundle

	secrets := make([]byte, 0, 64)

	staticSecret, err := privkeybndl.DiffieHellmanPrivateKey.ECDH(keybndl.DiffieHellmanKey)
	if err != nil {
		return err
	}
	secrets = append(secrets, staticSecret...)

	ephemeralSecret, err := ephemeralPrivateKey.ECDH(kexreq.EphemeralKey)
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
		KeyBundle: keybndl,
	}

	mgr.Set(kexreq.SendIDAddr.Base32(), &sess)

	kexresp := netprotocol.KeyExchangeResponse{
		SendIDAddr:   kexreq.RecvIDAddr,
		RecvIDAddr:   kexreq.SendIDAddr,
		EphemeralKey: ephemeralPrivateKey.PublicKey(),
		RatchetKey:   ratchet.OurKey.PublicKey(),
	}

	sigkexresp, err := kexresp.Sign(privkeybndl.SigningPrivateKey)
	if err != nil {
		return err
	}

	sigkexrespByte, err := sigkexresp.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := conn.Write(sigkexrespByte); err != nil {
		return err
	}

	return nil
}

func handleKeyExchangeResponse(ctx context.Context, conn net.Conn, mgr *session.SessionManager, query *repository.Queries) error {
	sigkexrespByte := make([]byte, netprotocol.SizeSignedKeyExchangeResponse)
	if _, err := conn.Read(sigkexrespByte); err != nil {
		return err
	}
	var sigkexresp netprotocol.SignedKeyExchangeResponse
	if err := sigkexresp.UnmarshalBinary(sigkexrespByte); err != nil {
		return err
	}
	kexresp := sigkexresp.Inner

	logger.Get().Infof("Key Exchange Response from %s to %s", kexresp.SendIDAddr.Base32(), kexresp.RecvIDAddr.Base32())

	if !mgr.Address.Equal(kexresp.RecvIDAddr) {
		return &InvalidRecvError{
			SubjectName:         "KeyExchangeResponse",
			SubjectActualRecv:   kexresp.RecvIDAddr,
			SubjectExpectedRecv: mgr.Address,
		}
	}

	sess, ok := mgr.Get(kexresp.SendIDAddr.Base32())

	if !ok {
		return &NoSessionError{PeerAddress: kexresp.SendIDAddr}
	}

	if sess.EphemeralExchangeKey == nil {
		return &NoKeyExchangeError{PeerAddress: kexresp.SendIDAddr}
	}

	keybndl := sess.KeyBundle

	if err := sigkexresp.Verify(keybndl.SigningKey); err != nil {
		return err
	}

	privkeybndl := mgr.PrivateKeyBundle

	secrets := make([]byte, 0, 64)

	staticSecret, err := privkeybndl.DiffieHellmanPrivateKey.ECDH(keybndl.DiffieHellmanKey)
	if err != nil {
		return err
	}
	secrets = append(secrets, staticSecret...)

	ephemeralSecret, err := sess.EphemeralExchangeKey.ECDH(kexresp.EphemeralKey)
	if err != nil {
		return err
	}
	secrets = append(secrets, ephemeralSecret...)

	sharedSecret := sha3.Sum256(secrets)

	ratchet, err := doubleratchet.New(sharedSecret[:], kexresp.RatchetKey)
	if err != nil {
		return err
	}

	sess.Ratchet = ratchet
	sess.EphemeralExchangeKey = nil

	return nil
}
