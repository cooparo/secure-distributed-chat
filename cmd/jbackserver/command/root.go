package command

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/packets"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	addr    string
	port    uint
)

var rootCmd = &cobra.Command{
	Use:   "jbackserver",
	Short: "Background server for jchat",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Init(verbose)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		bindAddr := fmt.Sprintf("%s:%d", addr, port)
		s := fmt.Sprintf("Starting server on %s", bindAddr)
		logger.Get().Info(s)
		ln, err := net.Listen("tcp", bindAddr)
		if err != nil {
			return err
		}

		for {
			conn, err := ln.Accept()
			if err != nil {
				// TODO: handle this more graceful instead of crashing
				return err
			}
			go packets.HandleConnection(conn)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		io.WriteString(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.Flags().StringVarP(&addr, "address", "a", "0.0.0.0", "Address to listen on")
	rootCmd.Flags().UintVarP(&port, "port", "p", 1337, "Port to listen on")
}
