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
	"github.com/cooparo/secure-distributed-chat/internal/nethandle/message"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
)

const connTimeout = 5 * time.Second

var packetTypeName = map[netprotocol.PacketType]string{
	netprotocol.PacketTypeHeartbeat:           "Heartbeat",
	netprotocol.PacketTypeMessage:             "Message",
	netprotocol.PacketTypeKeyExchangeRequest:  "Key Exchange Request",
	netprotocol.PacketTypeKeyExchangeResponse: "Key Exchange Response",
}

type packetHandler func(net.Conn) error

var packetTypeHandler = map[netprotocol.PacketType]packetHandler{
	netprotocol.PacketTypeHeartbeat: func(conn net.Conn) error {
		logger.Get().Debugf("Got heartbeat from %s", conn.RemoteAddr().String())
		return nil
	},
	netprotocol.PacketTypeMessage: message.HandleMessage,
}

func ServeListener(ctx context.Context, ln net.Listener, wg *sync.WaitGroup) {
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
			handleConn(ctx, conn, wg)
		}
	}()
}

func handleConn(ctx context.Context, conn net.Conn, wg *sync.WaitGroup) {
	wg.Go(func() {
		defer conn.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(connTimeout))
			header, err := netprotocol.Read(conn)
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

			packetName, ok := packetTypeName[header.PacketType]
			if !ok {
				logger.Get().Errorf("Unknown PacketType with id %#x", header.PacketType)
				return
			}

			logger.Get().Debugf("Got packet with version %d and PacketType %s (%#x)", header.Version, packetName, header.PacketType)

			handler, ok := packetTypeHandler[header.PacketType]
			if !ok {
				logger.Get().Errorf("No handler for PacketType %s (%#x)", packetName, header.PacketType)
				return
			}

			err = handler(conn)
			if err != nil {
				logger.Get().Errorf("Got error handling PacketType %s (%#x) from %s: %s", packetName, header.PacketType, conn.RemoteAddr().String(), err.Error())
				return
			}
		}
	})
}
