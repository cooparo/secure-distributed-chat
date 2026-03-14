package ipchandle

import (
	"context"
	"net"
	"time"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/internal/netclient"
	"github.com/cooparo/secure-distributed-chat/pkg/common"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
)

func sendNack(conn net.Conn) {
	nackHdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeSendMessageNac,
	}
	nackPkt, _ := nackHdr.MarshalBinary()
	conn.Write(nackPkt)
}

func handleServerSendMessage(ctx context.Context, conn net.Conn, state *ServerState) error {

	sendmsghdrByte := make([]byte, ipcprotocol.SizeSendMessageHeader)
	if _, err := conn.Read(sendmsghdrByte); err != nil {
		return err
	}

	sendmsghdr := &ipcprotocol.SendMessageHeader{}
	if err := sendmsghdr.UnmarshalBinary(sendmsghdrByte); err != nil {
		return err
	}

	logger.Get().Infof("Sending to: %s", sendmsghdr.PeerAddress.Base32())
	logger.Get().Infof("Message Length: %d", sendmsghdr.MessageLength)

	msgData := make([]byte, sendmsghdr.MessageLength)
	if _, err := conn.Read(msgData); err != nil {
		return err
	}

	logger.Get().Debugf("Message data: %s", msgData)

	// Look up peer's network address from DB
	peerRow, err := state.Query.GetIdentity(ctx, sendmsghdr.PeerAddress.Base32())
	if err != nil {
		logger.Get().Warnf("Peer %s not found in DB: %s", sendmsghdr.PeerAddress.Base32(), err.Error())
		sendNack(conn)
		return nil
	}

	// Decode peer's SignedNetworkUpdate to extract IP
	peerSigNetUpd := &identity.SignedNetworkUpdate{}
	if err := peerSigNetUpd.Decode(peerRow.NetAddrBundle); err != nil {
		logger.Get().Warnf("Failed to decode peer network update: %s", err.Error())
		sendNack(conn)
		return nil
	}

	// Decode peer's SignedKeyBundle
	peerSigKeyBndl := &identity.SignedKeyBundle{}
	if err := peerSigKeyBndl.Decode(peerRow.KeyBundle); err != nil {
		logger.Get().Warnf("Failed to decode peer key bundle: %s", err.Error())
		sendNack(conn)
		return nil
	}

	// Connect to peer
	peerConn, err := netclient.ConnectToPeer(ctx, peerSigNetUpd.Inner.NetAddress)
	if err != nil {
		logger.Get().Warnf("Failed to connect to peer: %s", err.Error())
		sendNack(conn)
		return nil
	}
	defer peerConn.Close()

	// If no session exists, initiate key exchange
	_, hasSession := state.Mgr.Get(sendmsghdr.PeerAddress.Base32())
	if !hasSession {
		logger.Get().Infof("No session for peer %s, initiating key exchange", sendmsghdr.PeerAddress.Base32())
		if err := netclient.InitiateKeyExchange(
			peerConn,
			state.Mgr,
			sendmsghdr.PeerAddress,
			peerSigKeyBndl.Inner,
			state.OurSignedKeyBundle,
			state.OurSignedNetworkUpdate,
		); err != nil {
			logger.Get().Warnf("Key exchange failed: %s", err.Error())
			sendNack(conn)
			return nil
		}
	}

	// Send encrypted message over TCP
	if err := netclient.SendMessage(peerConn, state.Mgr, sendmsghdr.PeerAddress, msgData); err != nil {
		logger.Get().Warnf("Failed to send message: %s", err.Error())
		sendNack(conn)
		return nil
	}

	// Store outgoing message in local DB
	now := time.Now().Unix()
	err = state.Query.AddMessage(ctx, repository.AddMessageParams{
		SenderAddress:   state.Mgr.Address.Base32(),
		ReceiverAddress: sendmsghdr.PeerAddress.Base32(),
		Time:            now,
		Contents:        string(msgData),
	})
	if err != nil {
		logger.Get().Warnf("Failed to store outgoing message: %s", err.Error())
	}

	// Send ACK back to CLI
	ackHdr := &ipcprotocol.MainHeader{
		Version:     1,
		CommandType: ipcprotocol.CommandTypeSendMessageAck,
	}
	ackPkt, err := ackHdr.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := conn.Write(ackPkt); err != nil {
		return err
	}

	return nil
}

func handleServerMessageRequest(ctx context.Context, conn net.Conn, state *ServerState) error {
	query := state.Query
	msgreqhdrByte := make([]byte, ipcprotocol.SizeMessageRequestHeader)
	if _, err := conn.Read(msgreqhdrByte); err != nil {
		return err
	}

	var msgreqhdr ipcprotocol.MessageRequestHeader
	if err := msgreqhdr.UnmarshalBinary(msgreqhdrByte); err != nil {
		return err
	}

	msgRows, err := query.GetMessages(ctx, msgreqhdr.Address.Base32())
	if err != nil {
		return err
	}

	mainhdr := &ipcprotocol.MainHeader{
		Version:     ipcprotocol.Version(1),
		CommandType: ipcprotocol.CommandTypeMessageResponse,
	}

	pkt, err := mainhdr.MarshalBinary()
	if err != nil {
		return err
	}

	msgresphdr := &ipcprotocol.MessageResponseHeader{
		MessageCount: uint16(len(msgRows)),
	}

	pkt, err = msgresphdr.AppendBinary(pkt)
	if err != nil {
		return err
	}

	for _, msgItem := range msgRows {
		senderAddress, err := identity.IdentityFromBase32(msgItem.SenderAddress)
		if err != nil {
			return err
		}
		receiverAddress, err := identity.IdentityFromBase32(msgItem.ReceiverAddress)
		if err != nil {
			return err
		}

		msgData := []byte(msgItem.Contents)

		msghdr := &ipcprotocol.MessageHeader{
			SenderAddress:   senderAddress,
			ReceiverAddress: receiverAddress,
			Timestamp:       common.Timestamp(msgItem.Time),
			MessageLength:   uint16(len(msgData)),
		}

		msg := &ipcprotocol.Message{
			Header: msghdr,
			Data:   msgData,
		}

		pkt, err = msg.AppendBinary(pkt)
		if err != nil {
			return err
		}
	}

	if _, err := conn.Write(pkt); err != nil {
		return err
	}

	return nil
}
