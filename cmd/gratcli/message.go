package main

import (
	"fmt"
	"os"

	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
	"github.com/spf13/cobra"
)

var messageCmd = &cobra.Command{
	Use:   "message",
	Short: "Send message",
	Run: func(cmd *cobra.Command, args []string) {
		recvAddressStr, err := cmd.Flags().GetString("receiver")
		if err != nil {
			fmt.Printf("Got error reading flags: %s\n", err.Error())
			os.Exit(1)
		}

		messageStr, err := cmd.Flags().GetString("message")
		if err != nil {
			fmt.Printf("Got error reading flags: %s\n", err.Error())
			os.Exit(1)
		}

		// Load identity
		keyFile, err := cmd.Flags().GetString("keyfile")
		if err != nil {
			fmt.Printf("Got error reading flags: %s\n", err.Error())
			os.Exit(1)
		}

		privKeyBundle := &identity.PrivateKeyBundle{}
		if err := privKeyBundle.Load(keyFile); err != nil {
			fmt.Printf("Error loading keyfile %s: %s\n", keyFile, err.Error())
			os.Exit(1)
		}

		recvAddress, err := identity.IdentityFromBase32(recvAddressStr)
		if err != nil {
			fmt.Printf("Error decoding base32 receiver address: %s\n", err.Error())
		}

		conn, err := connect()
		if err != nil {
			fmt.Printf("Error connecting to server: %s\nIs gratserver running?\n", err.Error())
			os.Exit(1)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				panic(err)
			}
		}()

		// Send packet
		mainhdr := &ipcprotocol.MainHeader{
			Version:     1,
			CommandType: ipcprotocol.CommandTypeSendMessage,
		}

		pkt, err := mainhdr.MarshalBinary()
		if err != nil {
			logger.Get().Fatalf("Got error marshaling MainHeader: %s", err.Error())
			os.Exit(1)
		}

		sendmsghdr := &ipcprotocol.SendMessageHeader{
			PeerAddress:   recvAddress,
			MessageLength: uint16(len(messageStr)),
		}

		sendmsg := &ipcprotocol.SendMessage{
			Header: sendmsghdr,
			Data:   []byte(messageStr),
		}

		pkt, err = sendmsg.AppendBinary(pkt)
		if err != nil {
			fmt.Printf("Got error marshaling SendMessage: %s", err.Error())
			os.Exit(1)
		}

		// Write to socket
		if _, err := conn.Write(pkt); err != nil {
			fmt.Printf("Error sending packet: %s\n", err.Error())
			os.Exit(1)
		}

		// TODO: syncable maybe (with server response)?

		// Read Response (ACK/NACK)
		headerBytes := make([]byte, ipcprotocol.SizeMainHeader)
		if _, err := conn.Read(headerBytes); err != nil {
			fmt.Printf("Error reading response: %s\n", err.Error())
			os.Exit(1)
		}

		var header ipcprotocol.MainHeader
		if err := header.UnmarshalBinary(headerBytes); err != nil {
			fmt.Printf("Error decoding header: %s\n", err.Error())
			os.Exit(1)
		}

		switch header.CommandType {
		case ipcprotocol.CommandTypeSendMessageAck:
			fmt.Println("Message sent successfully")
		case ipcprotocol.CommandTypeSendMessageNac:
			fmt.Println("Failed to send message")
		default:
			fmt.Printf("Unexpected response type: %#x\n", header.CommandType)
		}
	},
}

func init() {
	messageCmd.Flags().StringP("receiver", "r", "", "Address of the receiver")
	if err := messageCmd.MarkFlagRequired("receiver"); err != nil {
		panic(err)
	}
	messageCmd.Flags().StringP("message", "m", "", "Send message")
	if err := messageCmd.MarkFlagRequired("message"); err != nil {
		panic(err)
	}
	messageCmd.Flags().StringP("keyfile", "k", "./private.key", "Private key file")
}
