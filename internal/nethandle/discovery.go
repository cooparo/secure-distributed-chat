package nethandle

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/common/flags"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func handleDiscoveryRequest(ctx context.Context, conn net.Conn, mgr *session.SessionManager, query *repository.Queries) error {
	discreqhdrByte := make([]byte, netprotocol.SizeDiscoveryRequestHeader)
	if _, err := io.ReadFull(conn, discreqhdrByte); err != nil {
		return err
	}
	logger.Get().Debugf("Nethandle DiscoveryRequestHeader raw read: %#x", discreqhdrByte)

	discreqhdr := &netprotocol.DiscoveryRequestHeader{}
	if err := discreqhdr.UnmarshalBinary(discreqhdrByte); err != nil {
		return err
	}

	logger.Get().Infof("Got Discovery request from %s for %s", discreqhdr.SendIDAddr.Base32(), discreqhdr.LookupIDAddr.Base32())

	sigkeybndl := discreqhdr.SignedKeyBundle
	keybndl := sigkeybndl.Inner

	calcAddress, err := keybndl.Address()
	if err != nil {
		logger.Get().Errorf("Got error calculating address from Key Bundle: %s", err.Error())
		return err
	}

	if !calcAddress.Equal(discreqhdr.SendIDAddr) {
		logger.Get().Warnf("Address %s doesn't match the calculcated address %s", discreqhdr.SendIDAddr.Base32(), calcAddress.Base32())
		return &CalcAddrMismatchError{
			SubjectActualAddress:  discreqhdr.SendIDAddr,
			SubjectExpectedAddess: calcAddress,
		}
	}

	if err := sigkeybndl.Verify(); err != nil {
		return err
	}

	signetupd := discreqhdr.SignedNetworkUpdate
	netupd := signetupd.Inner

	if err := signetupd.Verify(keybndl.SigningKey); err != nil {
		return err
	}

	sigkeybndlEncoded, err := sigkeybndl.Encode()
	if err != nil {
		return err
	}

	signetupdEncoded, err := signetupd.Encode()
	if err != nil {
		return err
	}

	// TODO: Check the timestamp
	err = query.AddIdentity(ctx, repository.AddIdentityParams{
		Address:           discreqhdr.SendIDAddr.Base32(),
		KeyBundle:         sigkeybndlEncoded,
		NetAddrBundleTime: int64(netupd.Timestamp),
		NetAddrBundle:     signetupdEncoded,
	})
	if err != nil {
		logger.Get().Warnf("DB: AddIdentity Failed: %s", err.Error())
	}

	logger.Get().Infof("Discovery request has %d additional identities", discreqhdr.IdentityCount)

	sizeAdditionalIdentities := int(discreqhdr.IdentityCount) * netprotocol.SizeFullIdentity
	addIdBuf := make([]byte, sizeAdditionalIdentities)
	if _, err := io.ReadFull(conn, addIdBuf); err != nil {
		return err
	}
	logger.Get().Debugf("Additional Identities from %s is %#x", discreqhdr.SendIDAddr.Base32(), addIdBuf)

	discreq := &netprotocol.DiscoveryRequest{}
	discreq.AdditionalIdentities = make([]*netprotocol.FullIdentity, discreqhdr.IdentityCount)

	for range discreqhdr.IdentityCount {
		fullidByte := make([]byte, netprotocol.SizeFullIdentity)
		copy(fullidByte, addIdBuf[:netprotocol.SizeFullIdentity])
		fullid := &netprotocol.FullIdentity{}
		if err := fullid.UnmarshalBinary(fullidByte); err != nil {
			return err
		}

		addIdBuf = addIdBuf[netprotocol.SizeFullIdentity:]

		fullidSigkeybndl := fullid.SignedKeyBundle
		fullidKeybndl := fullidSigkeybndl.Inner

		fullidCalcAddress, err := fullidKeybndl.Address()
		if err != nil {
			logger.Get().Warn("Got error calculating address of additional identity")
			continue
		}

		if !fullidCalcAddress.Equal(fullid.Address) {
			logger.Get().Warnf("Additional identity address %s doesn't match calculated address %s", fullid.Address.Base32(), fullidCalcAddress.Base32())
			continue
		}

		if err := fullidSigkeybndl.Verify(); err != nil {
			logger.Get().Warnf("Signed Keybundle for Additional identity address %s cannot be verified", fullid.Address.Base32())
			continue
		}

		fullidSignetupd := fullid.SignedNetworkUpdate
		fullidNetupd := fullidSignetupd.Inner

		if err := fullidSignetupd.Verify(fullidKeybndl.SigningKey); err != nil {
			logger.Get().Warnf("Signed Networkupdate for Additional identity address %s cannot be verified", fullid.Address.Base32())
			continue
		}

		fullidSigkeybndlEncoded, err := fullidSigkeybndl.Encode()
		if err != nil {
			return err
		}

		fullidSignetupdEncoded, err := fullidSignetupd.Encode()
		if err != nil {
			return err
		}

		// TODO: Check the timestamp
		err = query.AddIdentity(ctx, repository.AddIdentityParams{
			Address:           fullid.Address.Base32(),
			KeyBundle:         fullidSigkeybndlEncoded,
			NetAddrBundleTime: int64(fullidNetupd.Timestamp),
			NetAddrBundle:     fullidSignetupdEncoded,
		})
		if err != nil {
			logger.Get().Warnf("DB: AddIdentity Failed: %s", err.Error())
		}

		discreq.AdditionalIdentities = append(discreq.AdditionalIdentities, fullid)
	}

	var responseFlags flags.Flags
	responseFlags = flags.Set(responseFlags, netprotocol.FlagDiscHit)

	lookupIdRow, err := query.GetIdentity(ctx, discreqhdr.LookupIDAddr.Base32())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Get().Warnf("Identity Address %s not found in our database", discreqhdr.LookupIDAddr.Base32())
			responseFlags = flags.Clear(responseFlags, netprotocol.FlagDiscHit)
		} else {
			return err
		}
	}

	// TODO: Maybe limit ourselves
	// FIX: Will be weird if we dont have enough
	// Will need more queries to get the count
	// This should work fine for now
	extraIdCount := discreqhdr.MaxIdentityCount
	if flags.Has(responseFlags, netprotocol.FlagDiscHit) {
		extraIdCount = extraIdCount - 1
	}

	extraIdRows, err := query.GetRandomIdentities(ctx, int64(extraIdCount))
	if err != nil {
		logger.Get().Warnf("DB: GetRandomIdentities Failed: %s", err.Error())
	}

	mainhdr := &netprotocol.MainHeader{
		Version:    1,
		PacketType: netprotocol.PacketTypeDiscoveryResponse,
	}

	discresp := &netprotocol.DiscoveryResponse{
		Identities: make([]*netprotocol.FullIdentity, 0, discreqhdr.MaxIdentityCount),
	}

	if flags.Has(responseFlags, netprotocol.FlagDiscHit) {
		lookupIdSigkeybndl := &identity.SignedKeyBundle{}
		if err := lookupIdSigkeybndl.Decode(lookupIdRow.KeyBundle); err != nil {
			return err
		}

		lookupIdSignetupd := &identity.SignedNetworkUpdate{}
		if err := lookupIdSignetupd.Decode(lookupIdRow.NetAddrBundle); err != nil {
			return err
		}

		discresp.Identities = append(discresp.Identities, &netprotocol.FullIdentity{
			Address:             discreqhdr.LookupIDAddr,
			SignedKeyBundle:     lookupIdSigkeybndl,
			SignedNetworkUpdate: lookupIdSignetupd,
		})
	}

	for i := range len(extraIdRows) {
		extraId := extraIdRows[i]

		extraIdAddress, err := identity.IdentityFromBase32(extraId.Address)
		if err != nil {
			return err
		}

		extraIdSigkeybndl := &identity.SignedKeyBundle{}
		if err := extraIdSigkeybndl.Decode(extraId.KeyBundle); err != nil {
			return err
		}

		extraIdSignetupd := &identity.SignedNetworkUpdate{}
		if err := extraIdSignetupd.Decode(extraId.NetAddrBundle); err != nil {
			return err
		}

		discresp.Identities = append(discresp.Identities, &netprotocol.FullIdentity{
			Address:             extraIdAddress,
			SignedKeyBundle:     extraIdSigkeybndl,
			SignedNetworkUpdate: extraIdSignetupd,
		})
	}

	discresp.Header = &netprotocol.DiscoveryResponseHeader{
		SendIDAddr:    mgr.Address,
		Flags:         responseFlags,
		IdentityCount: uint8(len(discresp.Identities)),
	}

	pkt, err := mainhdr.MarshalBinary()
	if err != nil {
		return err
	}

	pkt, err = discresp.AppendBinary(pkt)
	if err != nil {
		return err
	}

	if _, err := conn.Write(pkt); err != nil {
		return err
	}

	return nil
}

func handleDiscoveryResponse(ctx context.Context, conn net.Conn, mgr *session.SessionManager, query *repository.Queries) error {
	discresphdrByte := make([]byte, netprotocol.SizeDiscoveryResponseHeader)
	if _, err := io.ReadFull(conn, discresphdrByte); err != nil {
		return err
	}
	logger.Get().Debugf("Nethandle DiscoveryRequestHeader raw read: %#x", discresphdrByte)

	discresphdr := &netprotocol.DiscoveryResponseHeader{}
	if err := discresphdr.UnmarshalBinary(discresphdrByte); err != nil {
		return err
	}

	logger.Get().Infof("Got Discovery response from %s", discresphdr.SendIDAddr.Base32())

	logger.Get().Infof("Discovery Response has %d identities", discresphdr.IdentityCount)

	sizeIdentities := int(discresphdr.IdentityCount) * netprotocol.SizeFullIdentity
	idBuf := make([]byte, sizeIdentities)
	if _, err := io.ReadFull(conn, idBuf); err != nil {
		return err
	}
	logger.Get().Debugf("Identities from %s is %#x", discresphdr.SendIDAddr.Base32(), idBuf)

	discresp := &netprotocol.DiscoveryResponse{}
	discresp.Identities = make([]*netprotocol.FullIdentity, discresphdr.IdentityCount)

	for range discresphdr.IdentityCount {
		fullidByte := make([]byte, netprotocol.SizeFullIdentity)
		copy(fullidByte, idBuf[:netprotocol.SizeFullIdentity])
		fullid := &netprotocol.FullIdentity{}
		if err := fullid.UnmarshalBinary(fullidByte); err != nil {
			return err
		}

		idBuf = idBuf[netprotocol.SizeFullIdentity:]

		fullidSigkeybndl := fullid.SignedKeyBundle
		fullidKeybndl := fullidSigkeybndl.Inner

		fullidCalcAddress, err := fullidKeybndl.Address()
		if err != nil {
			logger.Get().Warn("Got error calculating address of identity")
			continue
		}

		if !fullidCalcAddress.Equal(fullid.Address) {
			logger.Get().Warnf("identity address %s doesn't match calculated address %s", fullid.Address.Base32(), fullidCalcAddress.Base32())
			continue
		}

		if err := fullidSigkeybndl.Verify(); err != nil {
			logger.Get().Warnf("Signed Keybundle for identity address %s cannot be verified", fullid.Address.Base32())
			continue
		}

		fullidSignetupd := fullid.SignedNetworkUpdate
		fullidNetupd := fullidSignetupd.Inner

		if err := fullidSignetupd.Verify(fullidKeybndl.SigningKey); err != nil {
			logger.Get().Warnf("Signed Networkupdate for identity address %s cannot be verified", fullid.Address.Base32())
			continue
		}

		fullidSigkeybndlEncoded, err := fullidSigkeybndl.Encode()
		if err != nil {
			return err
		}

		fullidSignetupdEncoded, err := fullidSignetupd.Encode()
		if err != nil {
			return err
		}

		// TODO: Check the timestamp
		err = query.AddIdentity(ctx, repository.AddIdentityParams{
			Address:           fullid.Address.Base32(),
			KeyBundle:         fullidSigkeybndlEncoded,
			NetAddrBundleTime: int64(fullidNetupd.Timestamp),
			NetAddrBundle:     fullidSignetupdEncoded,
		})
		if err != nil {
			logger.Get().Warnf("DB: AddIdentity Failed: %s", err.Error())
		}

		discresp.Identities = append(discresp.Identities, fullid)
	}

	if flags.Has(discresphdr.Flags, netprotocol.FlagDiscHit) {
		logger.Get().Info("The Hit flag is set")
		// TODO: First identity is the one we were looking for
		// Check that it is correct and somehow mark that
	}

	return nil
}
