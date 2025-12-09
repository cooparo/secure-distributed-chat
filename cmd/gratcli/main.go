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
		if err := cmd.Help(); err != nil {
			panic(err)
		}
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
	socketPath, err := ipcprotocol.DefaultSocketPath()
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
