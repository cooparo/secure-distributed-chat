package nethandle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/errs"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

const connTimeout = 5 * time.Second

var packetTypeName = map[netprotocol.PacketType]string{
	netprotocol.PacketTypeHeartbeat:           "Heartbeat",
	netprotocol.PacketTypeMessage:             "Message",
	netprotocol.PacketTypeKeyExchangeRequest:  "Key Exchange Request",
	netprotocol.PacketTypeKeyExchangeResponse: "Key Exchange Response",
	netprotocol.PacketTypeDiscoveryRequest:    "Discovery Request",
	netprotocol.PacketTypeDiscoveryResponse:   "Discovery Response",
}

type packetHandler func(context.Context, net.Conn, *session.SessionManager, *repository.Queries, chan<- PacketEvent) error

var packetTypeHandler = map[netprotocol.PacketType]packetHandler{
	netprotocol.PacketTypeHeartbeat:           handleHeartbeat,
	netprotocol.PacketTypeMessage:             handleMessage,
	netprotocol.PacketTypeKeyExchangeRequest:  handleKeyExchangeRequest,
	netprotocol.PacketTypeKeyExchangeResponse: handleKeyExchangeResponse,
	netprotocol.PacketTypeDiscoveryRequest:    handleDiscoveryRequest,
	netprotocol.PacketTypeDiscoveryResponse:   handleDiscoveryResponse,
}

type PacketEvent uint8

const (
	PacketEventHeartbeatReceived PacketEvent = iota
	PacketEventMessageReceived
	PacketEventMessageSent
	PacketEventKeyExchangeRequestReceived
	PacketEventKeyExchangeRequestSent
	PacketEventKeyExchangeResponseReceived
	PacketEventKeyExchangeResponseSent
	PacketEventKeyExchangeSuccess
	PacketEventKeyExchangeFailed
	PacketEventDiscoveryRequestReceived
	PacketEventDiscoveryRequestSent
	PacketEventDiscoveryResponseReceived
	PacketEventDiscoveryResponseSent
	PacketEventDiscoveryHit
	PacketEventDiscoveryMiss
	PacketEventTimeout
	PacketEventClosed
	PacketEventError
)

func ServeListener(ctx context.Context, ln net.Listener, wg *sync.WaitGroup, mgr *session.SessionManager, query *repository.Queries) {
	go func() {
		<-ctx.Done()
		if err := ln.Close(); err != nil {
			panic(err)
		}
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				logger.Get().Warnf("Accept error: %s", err.Error())
				continue
			}
			handleConn(ctx, conn, wg, mgr, query, nil)
		}
	}()
}

func handleConn(ctx context.Context, conn net.Conn, wg *sync.WaitGroup, mgr *session.SessionManager, query *repository.Queries, evtchan chan<- PacketEvent) {
	wg.Go(func() {
		defer func() {
			if err := conn.Close(); err != nil {
				panic(err)
			}
		}()

		logger.Get().Infof("Got connection from %s", conn.RemoteAddr().String())

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if err := conn.SetReadDeadline(time.Now().Add(connTimeout)); err != nil {
				logger.Get().Error("Failed to set ReadDeadline")
				return
			}
			mainhdrByte := make([]byte, netprotocol.SizeMainHeader)
			_, err := conn.Read(mainhdrByte)
			if err != nil {
				// Timeout
				if errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Get().Warnf("Connection from %s timed out", conn.RemoteAddr().String())
					sendEvent(evtchan, PacketEventTimeout)
					return
				}

				// No data read (normally because the other end closed)
				if err == io.EOF {
					logger.Get().Warnf("Connection from %s closed", conn.RemoteAddr().String())
					sendEvent(evtchan, PacketEventClosed)
					return
				}

				// Generic error log
				logger.Get().Errorf("Got error reading from %s: %s", conn.RemoteAddr().String(), err.Error())
				return
			}
			logger.Get().Debugf("Nethandle MainHeader raw read: %#x\n", mainhdrByte)

			mainhdr := &netprotocol.MainHeader{}
			if err := mainhdr.UnmarshalBinary(mainhdrByte); err != nil {
				logger.Get().Errorf("Got an error unmarshaling mainheader: %s", err.Error())
				return
			}

			pktName, ok := packetTypeName[mainhdr.PacketType]
			if !ok {
				logger.Get().Warnf("Unknown PacketType with id %#x", mainhdr.PacketType)
				return
			}

			logger.Get().Infof("Got packet with version %d and PacketType %s (%#x)", mainhdr.Version, pktName, mainhdr.PacketType)

			handler, ok := packetTypeHandler[mainhdr.PacketType]
			if !ok {
				logger.Get().Warnf("No handler for PacketType %s (%#x)", pktName, mainhdr.PacketType)
				return
			}

			err = handler(ctx, conn, mgr, query, evtchan)
			if err != nil {
				logger.Get().Warnf("Got error handling PacketType %s (%#x) from %s: %s", pktName, mainhdr.PacketType, conn.RemoteAddr().String(), err.Error())
				return
			}
		}
	})
}

func SendMessage(ctx context.Context, wg *sync.WaitGroup, mgr *session.SessionManager, query *repository.Queries, peerAddress identity.IdentityAddress, message []byte) error {
	evtchan := make(chan PacketEvent)

	// TODO: Check if connection is there and use it instead
	// This is proberly need a rewrite of a good amount of things
	// Save it for future works

	// FIX: Possible infinite loop
	for {
		// FIX: We can get the person we are trying to contact
		randomId, err := query.GetRandomIdentity(ctx)
		if err != nil {
			return err
		}

		randomIdSignetupd := &identity.SignedNetworkUpdate{}
		err = randomIdSignetupd.Decode(randomId.NetAddrBundle)
		if err != nil {
			return err
		}
		if randomIdSignetupd.Inner == nil {
			return &errs.IsNilError{SubjectName: "randomIdSignetupd"}
		}
		randomIdNetupd := randomIdSignetupd.Inner

		dialAddr := fmt.Sprintf("[%s]:%d", randomIdNetupd.NetAddress.To16(), 1337)

		mainhdr := &netprotocol.MainHeader{
			Version:    1,
			PacketType: netprotocol.PacketTypeDiscoveryRequest,
		}

		// TODO: Share some more IDs, we make it simple here
		discreq := &netprotocol.DiscoveryRequest{
			Header: &netprotocol.DiscoveryRequestHeader{
				SendIDAddr:          mgr.Address,
				SignedKeyBundle:     mgr.SignedKeyBundle,
				SignedNetworkUpdate: mgr.SignedNetworkUpdate,
				LookupIDAddr:        peerAddress,
				IdentityCount:       0,
				MaxIdentityCount:    1,
			},
			AdditionalIdentities: make([]*netprotocol.FullIdentity, 0),
		}

		pkt, _ := mainhdr.MarshalBinary()

		pkt, err = discreq.AppendBinary(pkt)
		if err != nil {
			return err
		}

		conn, err := net.Dial("tcp", dialAddr)
		if err != nil {
			return err
		}

		_, err = conn.Write(pkt)
		if err != nil {
			if err := conn.Close(); err != nil {
				return err
			}

			return err
		}

		handleConn(ctx, conn, wg, mgr, query, evtchan)

		hit := false
		connDead := false

		for {
			evt := <-evtchan
			logger.Get().Debugf("Got PacketEvent: %d", evt)

			switch evt {
			case PacketEventDiscoveryHit:
				hit = true
			case PacketEventClosed, PacketEventTimeout, PacketEventError:
				connDead = true
			default:
			}

			if hit || connDead {
				break
			}
		}

		if hit {
			// TODO: Get Keybundle and Netupdate from the hit
			// IDK how to pass that, maybe db lookup, but that is
			// is slow and a little weird to need to go there
			break
		}
	}

	// TODO: KeyExchange

	// TODO: SendMessage

	return nil
}

func sendEvent(evtchan chan<- PacketEvent, evt PacketEvent) {
	if evtchan != nil {
		evtchan <- evt
	}
}
