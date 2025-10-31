package command

import (
	"fmt"
	"os"
	"io"

	"github.com/cooparo/secure-distributed-chat/pkg/connection"
	"github.com/spf13/cobra"
)

var (
	address string
)

var rootCmd = &cobra.Command{
	Use: "jchat",
	Short: "Chat",
	Run: func(cmd *cobra.Command, args []string) {
		s := fmt.Sprintf("Connecting to %s\n", address)
		io.WriteString(os.Stdout, s)
		connection.ConnectToServer(address)
	},
}

func Execute()  {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&address, "address", "a", "127.0.0.1:1337", "Address to connect to")
}
