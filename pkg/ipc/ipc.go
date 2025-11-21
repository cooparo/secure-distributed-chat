package ipc

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
)

// DefaultSocketPath returns the standard location for the socket
func DefaultSocketPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return "/tmp/grat.sock"
	}
	return filepath.Join(dir, "grat.sock")
}

func HandleIpcConnection(c net.Conn) {
	defer c.Close()

	err := handleIpcPackets(c)
	if err != nil {
		// Write the error to stderr and end the function
		logger.Get().Error("IPC Connection Error: " + err.Error())
		return
	}
}

func handleIpcPackets(c net.Conn) error {
	// Read header
	headerBuf := make([]byte, headerSize)
	_, err := io.ReadFull(c, headerBuf)

	if err != nil {
		if err != io.EOF {
			logger.Get().Error("Header Error: " + err.Error())
		}
		return err
	}

	// Get payload length
	var h Header
	if err := h.UnmarshalBinary(headerBuf); err != nil {
		logger.Get().Error("Invalid Header")
		return err
	}

	// Read payload
	payloadBuf := make([]byte, h.cmdPayloadLenght)
	_, err = io.ReadFull(c, payloadBuf)

	if err != nil {
		logger.Get().Error("Read Payload Error: " + err.Error())
		return err
	}

	fullPacket := append(headerBuf, payloadBuf...)
	logger.Get().Info("Received cmd: " + CmdTypeName[h.cmdType])

	switch h.cmdType {

	case CmdMsgReq:

		// TODO: fetch new messages from DB

		// Mock response
		newMsgs := []MsgPacket{
			{content: "Pizza"},
			{content: "Pasta"},
			{content: "Mandolino"},
		}
		resp := NewMsgRespPacket(newMsgs)

		data, err := resp.MarshalBinary()
		if err != nil {
			logger.Get().Error("Failed to marshal MsgRespPacket: " + err.Error())
			return err
		}

		c.Write(data)

	case CmdMsgResp:
		var pkt MsgRespPacket
		if err := pkt.UnmarshalBinary(fullPacket); err != nil {
			logger.Get().Error("Failed to unmarshal MsgRespPacket: " + err.Error())
			return err
		}

		// TODO: update UI with new messages

		logger.Get().Infof("Received %d new messages", len(pkt.msgPackets))

	case CmdSendMsg:
		var pkt SendMsgPacket
		if err := pkt.UnmarshalBinary(fullPacket); err != nil {
			logger.Get().Error("Failed to unmarshal SendMsgPacket: " + err.Error())
			return err
		}

		// TODO: save to DB
		// TODO: forward message to network

		// Send ACK
		ack := NewSendMsgAckPacket()
		data, err := ack.MarshalBinary()

		if err != nil {
			logger.Get().Error("Failed to marshal MsgAckPacket: " + err.Error())
			return err
		}

		c.Write(data)

	case CmdSendMsgAck:
		// TODO: mark message as sent
		logger.Get().Info("Message sent.")

	default:
		logger.Get().Warn(fmt.Sprintf("Unknown IPC Command: %d", h.cmdType))

	}

	return nil
}
