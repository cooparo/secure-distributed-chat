package main

import (
	"io"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	address string
)

var rootCmd = &cobra.Command{
	Use:   "gratcli",
	Short: "Chat",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Init(verbose)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil // TODO: make it communicate with IPC
	},
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		io.WriteString(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.Flags().StringVarP(&address, "address", "a", "127.0.0.1:1337", "Address to connect to")
}
