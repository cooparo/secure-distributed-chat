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
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

const connTimeout = 5 * time.Second

type ServerState struct {
	Query                  *repository.Queries
	Mgr                    *session.SessionManager
	PrivKeyBundle          *identity.PrivateKeyBundle
	OurSignedKeyBundle     *identity.SignedKeyBundle
	OurSignedNetworkUpdate *identity.SignedNetworkUpdate
}

var packetTypeName = map[ipcprotocol.CommandType]string{
	ipcprotocol.CommandTypeMessageRequest:      "Message Request",
	ipcprotocol.CommandTypeMessageResponse:     "Message Response",
	ipcprotocol.CommandTypeSendMessage:         "Send Message",
	ipcprotocol.CommandTypeSendMessageAck:      "Send Message ACK",
	ipcprotocol.CommandTypeListContacts:        "List Contacts",
	ipcprotocol.CommandTypeListContactsResponse: "List Contacts Response",
}

type ipcServerpacketHandler func(context.Context, net.Conn, *ServerState) error

var packetServerHandler = map[ipcprotocol.CommandType]ipcServerpacketHandler{
	ipcprotocol.CommandTypeMessageRequest: handleServerMessageRequest,
	ipcprotocol.CommandTypeSendMessage:    handleServerSendMessage,
	ipcprotocol.CommandTypeListContacts:   handleServerListContacts,
}

type ipcClientPacketHandler func(context.Context, net.Conn) error

var packetClientHandler = map[ipcprotocol.CommandType]ipcClientPacketHandler{
	ipcprotocol.CommandTypeMessageResponse:      handleClientMessageResponse,
	ipcprotocol.CommandTypeListContactsResponse: handleClientListContactsResponse,
}

func ServerIpcListener(ctx context.Context, ln net.Listener, wg *sync.WaitGroup, state *ServerState) {
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

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() {
					if err := c.Close(); err != nil {
						panic(err)
					}
				}()

				handleServerConn(ctx, c, state)
			}(conn)
		}
	}()
}

func ClientIpcListener(ctx context.Context, conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	go func() {
		<-ctx.Done()
		if err := conn.Close(); err != nil {
			panic(err)
		}
	}()

	handleConnClient(ctx, conn)
}

func handleConnClient(ctx context.Context, conn net.Conn) {
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

		mainhdrByte := make([]byte, ipcprotocol.SizeMainHeader)
		_, err := io.ReadFull(conn, mainhdrByte)
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

		var mainhdr ipcprotocol.MainHeader
		if err := mainhdr.UnmarshalBinary(mainhdrByte); err != nil {
			logger.Get().Errorf("Got an error unmarshaling mainheader: %s", err.Error())
			return
		}

		logger.Get().Infof("Dette er main header raw bytes: %v", mainhdrByte)
		logger.Get().Infof("Decoded version=%d commandtype=%d", mainhdr.Version, mainhdr.CommandType)

		pktName, ok := packetTypeName[mainhdr.CommandType]
		if !ok {
			logger.Get().Warnf("No handler for PacketType %s (%#x) \n in other words its not okay", pktName, mainhdr.CommandType)
			logger.Get().Error(ok)
			return
		}

		handler, ok := packetClientHandler[mainhdr.CommandType]
		if !ok {
			logger.Get().Warnf("No handler for PacketType %s (%#x)", pktName, mainhdr.CommandType)
			return
		}

		err = handler(ctx, conn)
		if err != nil {
			logger.Get().Warnf("Got error handling PacketType %s (%#x) error is: %s", pktName, mainhdr.CommandType, err.Error())
			return
		}

	}

}

func handleServerConn(ctx context.Context, conn net.Conn, state *ServerState) {
	logger.Get().Infof("Got connection from %s", conn.RemoteAddr().String())

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		mainhdrByte := make([]byte, ipcprotocol.SizeMainHeader)
		if err := conn.SetReadDeadline(time.Now().Add(connTimeout)); err != nil {
			logger.Get().Error("Failed to set ReadDeadline")
			return
		}

		_, err := io.ReadFull(conn, mainhdrByte)
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

		logger.Get().Infof("Nethandle MainHeader raw read: %d\n", mainhdrByte)

		var mainhdr ipcprotocol.MainHeader
		if err := mainhdr.UnmarshalBinary(mainhdrByte); err != nil {
			logger.Get().Errorf("Got an error unmarshaling mainheader: %s", err.Error())
			return
		}

		pktName, ok := packetTypeName[mainhdr.CommandType]
		if !ok {
			logger.Get().Warnf("No handler for PacketType %s (%#x) \n in other words its not okay", pktName, mainhdr.CommandType)
			return
		}
		logger.Get().Info(pktName)

		handler, ok := packetServerHandler[mainhdr.CommandType]
		if !ok {
			logger.Get().Warnf("No handler for PacketType %s (%#x)", pktName, mainhdr.CommandType)
			return
		}

		err = handler(ctx, conn, state)
		if err != nil {
			logger.Get().Warnf("Got error handling PacketType %s (%#x) error is: %s", pktName, mainhdr.CommandType, err.Error())
			return
		}

	}

}
