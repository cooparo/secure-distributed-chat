package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
	"github.com/spf13/cobra"
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch messages from a peer",
	Run: func(cmd *cobra.Command, args []string) {
		peerStr, err := cmd.Flags().GetString("peer")
		if err != nil {
			fmt.Printf("Error reading flags: %s\n", err.Error())
			os.Exit(1)
		}

		peerAddr, err := identity.IdentityFromBase32(peerStr)
		if err != nil {
			fmt.Printf("Error decoding peer address: %s\n", err.Error())
			os.Exit(1)
		}

		conn, err := connect()
		if err != nil {
			fmt.Printf("Error connecting to server: %s\nIs gratserver running?\n", err.Error())
			os.Exit(1)
		}
		defer conn.Close()

		// Send MessageRequest
		mainhdr := &ipcprotocol.MainHeader{
			Version:     1,
			CommandType: ipcprotocol.CommandTypeMessageRequest,
		}

		pkt, err := mainhdr.MarshalBinary()
		if err != nil {
			fmt.Printf("Error marshaling header: %s\n", err.Error())
			os.Exit(1)
		}

		msgreqhdr := &ipcprotocol.MessageRequestHeader{
			Address: peerAddr,
		}

		pkt, err = msgreqhdr.AppendBinary(pkt)
		if err != nil {
			fmt.Printf("Error marshaling request: %s\n", err.Error())
			os.Exit(1)
		}

		if _, err := conn.Write(pkt); err != nil {
			fmt.Printf("Error sending request: %s\n", err.Error())
			os.Exit(1)
		}

		// Read response MainHeader
		respHdrByte := make([]byte, ipcprotocol.SizeMainHeader)
		if _, err := io.ReadFull(conn, respHdrByte); err != nil {
			fmt.Printf("Error reading response header: %s\n", err.Error())
			os.Exit(1)
		}

		var respHdr ipcprotocol.MainHeader
		if err := respHdr.UnmarshalBinary(respHdrByte); err != nil {
			fmt.Printf("Error decoding response header: %s\n", err.Error())
			os.Exit(1)
		}

		if respHdr.CommandType != ipcprotocol.CommandTypeMessageResponse {
			fmt.Printf("Unexpected response type: %#x\n", respHdr.CommandType)
			os.Exit(1)
		}

		// Read MessageResponseHeader
		msgrespHdrByte := make([]byte, ipcprotocol.SizeMessageResponseHeader)
		if _, err := io.ReadFull(conn, msgrespHdrByte); err != nil {
			fmt.Printf("Error reading response: %s\n", err.Error())
			os.Exit(1)
		}

		var msgrespHdr ipcprotocol.MessageResponseHeader
		if err := msgrespHdr.UnmarshalBinary(msgrespHdrByte); err != nil {
			fmt.Printf("Error decoding response: %s\n", err.Error())
			os.Exit(1)
		}

		if msgrespHdr.MessageCount == 0 {
			fmt.Println("No messages.")
			return
		}

		fmt.Printf("Messages (%d):\n", msgrespHdr.MessageCount)

		for range msgrespHdr.MessageCount {
			// Read MessageHeader
			msghdrByte := make([]byte, ipcprotocol.SizeMessageHeader)
			if _, err := io.ReadFull(conn, msghdrByte); err != nil {
				fmt.Printf("Error reading message header: %s\n", err.Error())
				os.Exit(1)
			}

			var msghdr ipcprotocol.MessageHeader
			if err := msghdr.UnmarshalBinary(msghdrByte); err != nil {
				fmt.Printf("Error decoding message header: %s\n", err.Error())
				os.Exit(1)
			}

			// Read message data
			msgData := make([]byte, msghdr.MessageLength)
			if _, err := io.ReadFull(conn, msgData); err != nil {
				fmt.Printf("Error reading message data: %s\n", err.Error())
				os.Exit(1)
			}

			ts := time.Unix(int64(msghdr.Timestamp), 0)
			fmt.Printf("[%s] %s -> %s: %s\n",
				ts.Format("2006-01-02 15:04:05"),
				msghdr.SenderAddress.Base32(),
				msghdr.ReceiverAddress.Base32(),
				string(msgData),
			)
		}
	},
}

func init() {
	fetchCmd.Flags().StringP("peer", "p", "", "Peer address to fetch messages for")
	if err := fetchCmd.MarkFlagRequired("peer"); err != nil {
		panic(err)
	}
}
