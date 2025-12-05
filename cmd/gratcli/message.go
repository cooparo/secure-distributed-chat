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
		var (
			recvAddress identity.IdentityAddress
			message     ipcprotocol.Message
		)

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
			fmt.Printf("Need both message and receiver address not empty strings, got\nAddress: %s\nMessage: %s\n", recvAddressStr, messageStr)
			os.Exit(1)
		}

		recvAddress = identity.IdentityAddress([]byte(recvAddressStr))
		message = ipcprotocol.Message(messageStr)

		// NOTE: printing these only to supress error
		fmt.Printf("Sending to %s,\nMessage: \"%s\"\n", recvAddress, message)
		// TODO: sendMessage(to, message)

	},
}

func init() {
	messageCmd.Flags().StringP("receiver", "r", "", "Address of the receiver")
	messageCmd.Flags().StringP("message", "m", "", "Send message")
}
