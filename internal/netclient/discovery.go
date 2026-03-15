package netclient

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
)

// DiscoverPeer connects to a peer by hostname/IP, sends a discovery request,
// and stores the peer's identity in the local database.
func DiscoverPeer(
	ctx context.Context,
	host string,
	ourAddress identity.IdentityAddress,
	ourSignedKeyBundle *identity.SignedKeyBundle,
	ourSignedNetworkUpdate *identity.SignedNetworkUpdate,
	query *repository.Queries,
) error {
	addr := fmt.Sprintf("%s:%d", host, defaultPort)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	defer conn.Close()

	// Build discovery request
	mainhdr := &netprotocol.MainHeader{
		Version:    1,
		PacketType: netprotocol.PacketTypeDiscoveryRequest,
	}

	discreqhdr := &netprotocol.DiscoveryRequestHeader{
		SendIDAddr:          ourAddress,
		SignedKeyBundle:     ourSignedKeyBundle,
		SignedNetworkUpdate: ourSignedNetworkUpdate,
		LookupIDAddr:        ourAddress, // we don't know who we're looking for, just discover
		IdentityCount:       0,
		MaxIdentityCount:    5,
	}

	discreq := &netprotocol.DiscoveryRequest{
		Header:               discreqhdr,
		AdditionalIdentities: []*netprotocol.FullIdentity{},
	}

	pkt, err := mainhdr.MarshalBinary()
	if err != nil {
		return err
	}

	pkt, err = discreq.AppendBinary(pkt)
	if err != nil {
		return err
	}

	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("write discovery request: %w", err)
	}

	// Read response MainHeader
	respHdrByte := make([]byte, netprotocol.SizeMainHeader)
	if _, err := io.ReadFull(conn, respHdrByte); err != nil {
		return fmt.Errorf("read response header: %w", err)
	}

	var respHdr netprotocol.MainHeader
	if err := respHdr.UnmarshalBinary(respHdrByte); err != nil {
		return err
	}

	if respHdr.PacketType != netprotocol.PacketTypeDiscoveryResponse {
		return fmt.Errorf("unexpected response type: %#x", respHdr.PacketType)
	}

	// Read DiscoveryResponseHeader
	discresphdrByte := make([]byte, netprotocol.SizeDiscoveryResponseHeader)
	if _, err := io.ReadFull(conn, discresphdrByte); err != nil {
		return fmt.Errorf("read discovery response header: %w", err)
	}

	discresphdr := &netprotocol.DiscoveryResponseHeader{}
	if err := discresphdr.UnmarshalBinary(discresphdrByte); err != nil {
		return err
	}

	logger.Get().Infof("Discovery response from %s has %d identities", host, discresphdr.IdentityCount)

	// Read identities
	for range discresphdr.IdentityCount {
		fullidByte := make([]byte, netprotocol.SizeFullIdentity)
		if _, err := io.ReadFull(conn, fullidByte); err != nil {
			return fmt.Errorf("read identity: %w", err)
		}

		fullid := &netprotocol.FullIdentity{}
		if err := fullid.UnmarshalBinary(fullidByte); err != nil {
			logger.Get().Warnf("Failed to unmarshal identity: %s", err.Error())
			continue
		}

		sigkeybndl := fullid.SignedKeyBundle
		keybndl := sigkeybndl.Inner

		calcAddr, err := keybndl.Address()
		if err != nil {
			logger.Get().Warnf("Failed to calculate address: %s", err.Error())
			continue
		}

		if !calcAddr.Equal(fullid.Address) {
			logger.Get().Warnf("Address mismatch for discovered identity")
			continue
		}

		if err := sigkeybndl.Verify(); err != nil {
			logger.Get().Warnf("Key bundle verification failed: %s", err.Error())
			continue
		}

		signetupd := fullid.SignedNetworkUpdate
		if err := signetupd.Verify(keybndl.SigningKey); err != nil {
			logger.Get().Warnf("Network update verification failed: %s", err.Error())
			continue
		}

		sigkeybndlEncoded, err := sigkeybndl.Encode()
		if err != nil {
			return err
		}
		signetupdEncoded, err := signetupd.Encode()
		if err != nil {
			return err
		}

		err = query.AddIdentity(ctx, repository.AddIdentityParams{
			Address:           fullid.Address.Base32(),
			KeyBundle:         sigkeybndlEncoded,
			NetAddrBundleTime: int64(signetupd.Inner.Timestamp),
			NetAddrBundle:     signetupdEncoded,
		})
		if err != nil {
			logger.Get().Warnf("DB: AddIdentity for %s: %s", fullid.Address.Base32(), err.Error())
		} else {
			logger.Get().Infof("Discovered and stored peer %s", fullid.Address.Base32())
		}
	}

	return nil
}
