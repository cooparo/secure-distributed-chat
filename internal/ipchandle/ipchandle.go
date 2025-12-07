package ipchandle

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
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

const connTimeout = 5 * time.Second

var packetTypeName = map[ipcprotocol.CommandType]string{
	ipcprotocol.CommandTypeMessageRequest:  "Message Request",
	ipcprotocol.CommandTypeMessageResponse: "Message Response",
	ipcprotocol.CommandTypeSendMessage:     "Send Message",
	ipcprotocol.CommandTypeSendMessageAck:  "Send Message ACK",
}

type ipcpacketHandler func(context.Context, net.Conn, *repository.Queries) error

var packetTypeHandler = map[ipcprotocol.CommandType]ipcpacketHandler{
	ipcprotocol.CommandTypeMessageRequest:  handleMessageRqust,
	ipcprotocol.CommandTypeMessageResponse: handleMessageRqust,
	ipcprotocol.CommandTypeSendMessage:     handleMessageRqust,
	ipcprotocol.CommandTypeSendMessageAck:  handleMessageRqust,
}

func ServeIpcListener(ctx context.Context, ln net.Listener, wg *sync.WaitGroup) {
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
				logger.Get().Warnf("Accept error: %s", err.Error())
				continue
			}

			handleConn(ctx, conn, wg)
		}
	}()

}

func handleConn(ctx context.Context, conn net.Conn, wg *sync.WaitGroup) {
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

			mainhdrByte := make([]byte, ipcprotocol.SizeMainHeader)
			_, err := conn.Read(mainhdrByte)
			if err != nil {

				if errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Get().Warnf("Connection from %s timed out", conn.RemoteAddr().String())
					return
				}

				if err == io.EOF {
					logger.Get().Warnf("Connection from %s closed", conn.RemoteAddr().String())
					return
				}

				logger.Get().Errorf("Got error reading from %s: %s", conn.RemoteAddr().String(), err.Error())
				return
			}

			logger.Get().Debugf("Nethandle MainHeader raw read: %#x\n", mainhdrByte)

			var mainhdr ipcprotocol.MainHeader
			if err := mainhdr.UnmarshalBinary(mainhdrByte); err != nil {
				logger.Get().Errorf("Got an error unmarshaling mainheader: %s", err.Error())
				return
			}

			pktName, ok := packetTypeName[mainhdr.CommandType]

			if !ok {
				logger.Get().Warnf("No handler for PacketType %s (%#x) \n in other words its not okay", pktName, mainhdr.CommandType)
			}
		}

	})
}
