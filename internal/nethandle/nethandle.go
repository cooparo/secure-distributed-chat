package nethandle

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

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
}

type packetHandler func(net.Conn, *session.SessionManager) error

var packetTypeHandler = map[netprotocol.PacketType]packetHandler{
	netprotocol.PacketTypeHeartbeat:           HandleHeartbeat,
	netprotocol.PacketTypeMessage:             HandleMessage,
	netprotocol.PacketTypeKeyExchangeRequest:  HandleKeyExchangeRequest,
	netprotocol.PacketTypeKeyExchangeResponse: HandleKeyExchangeResponse,
}

func ServeListener(ctx context.Context, ln net.Listener, wg *sync.WaitGroup, mgr *session.SessionManager) {
	go func() {
		<-ctx.Done()
		ln.Close()
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
				logger.Get().Errorf("Accept error: %s", err.Error())
				continue
			}
			handleConn(ctx, conn, wg, mgr)
		}
	}()
}

func handleConn(ctx context.Context, conn net.Conn, wg *sync.WaitGroup, mgr *session.SessionManager) {
	wg.Go(func() {
		defer conn.Close()

		logger.Get().Infof("Got connection from %s", conn.RemoteAddr().String())

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(connTimeout))
			mhByte := make([]byte, netprotocol.SizeMainHeader)
			_, err := conn.Read(mhByte)
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
			var mh netprotocol.MainHeader
			if err := mh.UnmarshalBinary(mhByte); err != nil {
				logger.Get().Errorf("Got an error ")
				return
			}

			packetName, ok := packetTypeName[mh.PacketType]
			if !ok {
				logger.Get().Errorf("Unknown PacketType with id %#x", mh.PacketType)
				return
			}

			logger.Get().Debugf("Got packet with version %d and PacketType %s (%#x)", mh.Version, packetName, mh.PacketType)

			handler, ok := packetTypeHandler[mh.PacketType]
			if !ok {
				logger.Get().Errorf("No handler for PacketType %s (%#x)", packetName, mh.PacketType)
				return
			}

			err = handler(conn, mgr)
			if err != nil {
				logger.Get().Errorf("Got error handling PacketType %s (%#x) from %s: %s", packetName, mh.PacketType, conn.RemoteAddr().String(), err.Error())
				return
			}
		}
	})
}
