package netprotocol

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol/keyexchange"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol/message"
)

type PacketType uint8

const (
	PacketTypeHeartbeat PacketType = iota
	PacketTypeMessage
	PacketTypeKeyExchangeRequest
	PacketTypeKeyExchangeResponse
)

const connTimeout = 5 * time.Second

var packetTypeName = map[PacketType]string{
	PacketTypeHeartbeat:           "Heartbeat",
	PacketTypeMessage:             "Message",
	PacketTypeKeyExchangeRequest:  "Key Exchange Request",
	PacketTypeKeyExchangeResponse: "Key Exchange Response",
}

type PacketHandler func(net.Conn) error

var packetTypeHandler = map[PacketType]PacketHandler{
	// TODO: heartbeat handler
	PacketTypeMessage:             message.HandleMessage,
	PacketTypeKeyExchangeRequest:  keyexchange.HandleRequest,
	PacketTypeKeyExchangeResponse: keyexchange.HandleResponse,
}

type mainHeader struct {
	Version    uint8
	PacketType PacketType
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
			header := mainHeader{}
			err := binary.Read(conn, binary.BigEndian, &header)
			if err != nil {

				// TODO: Figure out if some errors are recoverable

				// Timeout
				if errors.Is(err, os.ErrDeadlineExceeded) {
					// TODO: Recoverable?
					logger.Get().Warnf("Connection from %s timed out", conn.RemoteAddr().String())
					return
				}

				//
				if err == io.EOF {
					logger.Get().Warnf("Connection from %s closed", conn.RemoteAddr().String())
					return
				}

				// Generic err log
				logger.Get().Errorf("Got error reading from %s: %s", conn.RemoteAddr().String(), err.Error())
				return
			}

			ptypeName, ok := packetTypeName[header.PacketType]
			if !ok {
				logger.Get().Errorf("Unknown PacketType with id %#x", header.PacketType)
				return
			}

			logger.Get().Debugf("Got packet with version %d and PacketType %s (%#x)", header.Version, ptypeName, header.PacketType)

			handler, ok := packetTypeHandler[header.PacketType]
			if !ok {
				logger.Get().Errorf("No handler for PacketType %s (%#x)", ptypeName, header.PacketType)
				return
			}

			err = handler(conn)
			if err != nil {
				// TODO: recoverable?
				logger.Get().Errorf("Got error handling PacketType %s (%#x) from %s: %s", ptypeName, header.PacketType, conn.RemoteAddr().String(), err.Error())
				return
			}
		}
	})
}
