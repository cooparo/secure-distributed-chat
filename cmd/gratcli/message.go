package main

import (
	"fmt"
	"os"

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

		if recvAddressStr == "" || messageStr == "" {
			fmt.Println("Receiver (-r) and message (-m) are required.")
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

		myAddress, err := privKeyBundle.Public().Address()
		if err != nil {
			fmt.Printf("Error calculating address: %s\n", err.Error())
			os.Exit(1)
		}

		recvAddress := identity.IdentityAddress([]byte(recvAddressStr))
		message := ipcprotocol.Message(messageStr)

		conn, err := connect()
		if err != nil {
			fmt.Printf("Error connecting to server: %s\nIs gratserver running?\n", err.Error())
			os.Exit(1)
		}
		defer conn.Close()

		// Send packet
		msgPacket := ipcprotocol.NewMsgPacket(myAddress, recvAddress, message)
		sendPacket := ipcprotocol.NewSendMsgPacket(*msgPacket)

		data, err := sendPacket.MarshalBinary()
		if err != nil {
			fmt.Printf("Error marshaling packet: %s\n", err.Error())
			os.Exit(1)
		}

		// Write to socket
		if _, err := conn.Write(data); err != nil {
			fmt.Printf("Error sending packet: %s\n", err.Error())
			os.Exit(1)
		}

		// TODO: syncable maybe (with server response)?

		// Read Response (ACK/NACK)
		headerBytes := make([]byte, ipcprotocol.IpcHeaderSize)
		if _, err := conn.Read(headerBytes); err != nil {
			fmt.Printf("Error reading response: %s\n", err.Error())
			os.Exit(1)
		}

		var header ipcprotocol.Header
		if err := header.UnmarshalBinary(headerBytes); err != nil {
			fmt.Printf("Error decoding header: %s\n", err.Error())
			os.Exit(1)
		}

		switch header.CmdType {
		case ipcprotocol.CmdTypeSendMsgAck:
			fmt.Println("Message sent successfully")
		case ipcprotocol.CmdTypeSendMsgNack:
			fmt.Println("Failed to send message")
		default:
			fmt.Printf("Unexpected response type: %#x\n", header.CmdType)
		}
	},
}

func init() {
	messageCmd.Flags().StringP("receiver", "r", "", "Address of the receiver")
	messageCmd.Flags().StringP("keyfile", "k", "./private.key", "Private key file")
	messageCmd.Flags().StringP("message", "m", "", "Send message")
}
