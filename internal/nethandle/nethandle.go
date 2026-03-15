package nethandle

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
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

type packetHandler func(context.Context, net.Conn, *session.SessionManager, *repository.Queries) error

var packetTypeHandler = map[netprotocol.PacketType]packetHandler{
	netprotocol.PacketTypeHeartbeat:           handleHeartbeat,
	netprotocol.PacketTypeMessage:             handleMessage,
	netprotocol.PacketTypeKeyExchangeRequest:  handleKeyExchangeRequest,
	netprotocol.PacketTypeKeyExchangeResponse: handleKeyExchangeResponse,
	netprotocol.PacketTypeDiscoveryRequest:    handleDiscoveryRequest,
	netprotocol.PacketTypeDiscoveryResponse:   handleDiscoveryResponse,
}

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
			handleConn(ctx, conn, wg, mgr, query)
		}
	}()
}

func handleConn(ctx context.Context, conn net.Conn, wg *sync.WaitGroup, mgr *session.SessionManager, query *repository.Queries) {
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
			_, err := io.ReadFull(conn, mainhdrByte)
			if err != nil {
				// Timeout
				if errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Get().Warnf("Connection from %s timed out", conn.RemoteAddr().String())
					return
				}

				// No data read (normally because the other end closed)
				if err == io.EOF {
					logger.Get().Warnf("Connection from %s closed", conn.RemoteAddr().String())
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

			err = handler(ctx, conn, mgr, query)
			if err != nil {
				logger.Get().Warnf("Got error handling PacketType %s (%#x) from %s: %s", pktName, mainhdr.PacketType, conn.RemoteAddr().String(), err.Error())
				return
			}
		}
	})
}
