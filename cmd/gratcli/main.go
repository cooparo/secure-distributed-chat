package main

import (
	"net"

	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gratcli",
	Short: "Grat CLI interface",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

func init() {
	rootCmd.AddCommand(identityCmd)
	rootCmd.AddCommand(messageCmd)
	rootCmd.AddCommand(fetchCmd)
}

func connect() (net.Conn, error) {
	socketPath := ipcprotocol.DefaultSocketPath()
	return net.Dial("unix", socketPath)
}
