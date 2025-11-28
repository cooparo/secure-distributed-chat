package ipchandle

import (
	"context"
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/session"
)

func HandleCmdMsgReq(context.Context, net.Conn, *session.SessionManager) error {
	// TODO:
	return nil
}

func HandleCmdMsgResp(context.Context, net.Conn, *session.SessionManager) error {
	// TODO:
	return nil
}

func HandleCmdSendMsg(context.Context, net.Conn, *session.SessionManager) error {
	// TODO:
	return nil
}

func HandleCmdSendMsgAck(context.Context, net.Conn, *session.SessionManager) error {
	// TODO:
	return nil
}

func HandleCmdSendMsgNack(context.Context, net.Conn, *session.SessionManager) error {
	// TODO:
	return nil
}
