package main

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cooparo/secure-distributed-chat/pkg/logger"
	"github.com/cooparo/secure-distributed-chat/pkg/netprotocol"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	addr    string
	port    uint
)

var rootCmd = &cobra.Command{
	Use:   "gratserver",
	Short: "Background server for grat",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Init(verbose)
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Context for graceful stop at SIGINT/SIGTERM
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		// WaitGroup semaphore for connection count
		var wg sync.WaitGroup

		bindAddr := fmt.Sprintf("[%s]:%d", addr, port)
		logger.Get().Infof("Starting server on %s", bindAddr)
		ln, err := net.Listen("tcp", bindAddr)
		if err != nil {
			logger.Get().Fatalf("Got error making TCP listener: %s", err.Error())
		}

		netprotocol.ServeListener(ctx, ln, &wg)

		// TODO: setup IPC socket

		// Wait for shutdown
		<-ctx.Done()

		logger.Get().Info("Stopping...")
		// Wait for all active connections to finish
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		<-done

		// TODO: IPC socket cleanup
	},
}

func main() {
	rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.Flags().StringVarP(&addr, "address", "a", "::", "Address to listen on")
	rootCmd.Flags().UintVarP(&port, "port", "p", 1337, "Port to listen on")
}
