package client

import (
	"fmt"
	"io"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/connection"
	"github.com/spf13/cobra"
)

var (
	address string
)

var ClientCmd = &cobra.Command{
	Use: "client",
	Short: "Client",
	Run: func(cmd *cobra.Command, args []string) {
		s := fmt.Sprintf("Connecting to %s\n", address)
		io.WriteString(os.Stdout, s)
		connection.ConnectToServer(address)
	},
}

func init() {
	ClientCmd.Flags().StringVarP(&address, "address", "a", "127.0.0.1:1337", "Address to connect to")
}
