package ipchandle

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

const connTimeout = 5 * time.Second

var CommandTypeName = map[ipcprotocol.CmdType]string{
	ipcprotocol.CmdTypeMsgReq:      "Message Request",
	ipcprotocol.CmdTypeMsgResp:     "Message Response",
	ipcprotocol.CmdTypeSendMsg:     "Send Message",
	ipcprotocol.CmdTypeSendMsgAck:  "Send Message ACK",
	ipcprotocol.CmdTypeSendMsgNack: "Send Message NACK",
}

type commandHandler func(context.Context, net.Conn) error

var CommandTypeHandler = map[ipcprotocol.CmdType]commandHandler{
	ipcprotocol.CmdTypeMsgReq:      HandleCmdMsgReq,
	ipcprotocol.CmdTypeMsgResp:     HandleCmdMsgResp,
	ipcprotocol.CmdTypeSendMsg:     HandleCmdSendMsg,
	ipcprotocol.CmdTypeSendMsgAck:  HandleCmdSendMsgAck,
	ipcprotocol.CmdTypeSendMsgNack: HandleCmdSendMsgNack,
}

func ServeIpcListener(ctx context.Context, ln net.Listener, wg *sync.WaitGroup) {
	// Close the socket on signal interrupt
	go func() {
		<-ctx.Done()
		os.Remove(ipcprotocol.DefaultSocketPath())
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
			handleIpcConn(ctx, conn, wg)
		}
	}()
}

func handleIpcConn(ctx context.Context, conn net.Conn, wg *sync.WaitGroup) {
	wg.Go(func() {
		defer conn.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn.SetReadDeadline(time.Now().Add(connTimeout))
			hBytes := make([]byte, ipcprotocol.IpcHeaderSize)

			if _, err := conn.Read(hBytes); err != nil {
				// Timeout
				if errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Get().Warnf("IPC Connection timed out")
					return
				}

				// No data read (normally because the other end closed)
				if err == io.EOF {
					logger.Get().Warnf("IPC Connection closed")
					return
				}

				// Generic error log
				logger.Get().Errorf("IPC Connection got error reading: %s", err.Error())
				return
			}

			var h ipcprotocol.Header
			if err := h.UnmarshalBinary(hBytes); err != nil {
				logger.Get().Errorf("Got an error in the IPC header")
				return
			}

			commandName, ok := CommandTypeName[h.CmdType]

			if !ok {
				logger.Get().Warnf("Unknown CmdType with id %#x", h.CmdType)
				return
			}

			logger.Get().Infof("Got command with version %d and CmdType %s (%#x)", h.Version, commandName, h.CmdType)

			handler, ok := CommandTypeHandler[h.CmdType]
			if !ok {
				logger.Get().Warnf("No handler for CmdType %s (%#x)", commandName, h.CmdType)
				return
			}

			if err := handler(ctx, conn); err != nil {
				logger.Get().Warnf("Got error handling CmdType %s (%#x): %s", commandName, h.CmdType, err.Error())
				return
			}
		}
	})
}
