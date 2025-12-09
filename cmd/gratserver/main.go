package main

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cooparo/secure-distributed-chat/internal/database"
	"github.com/cooparo/secure-distributed-chat/internal/ipchandle"
	"github.com/cooparo/secure-distributed-chat/internal/logger"
	"github.com/cooparo/secure-distributed-chat/internal/nethandle"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/cooparo/secure-distributed-chat/pkg/ipcprotocol"
	"github.com/cooparo/secure-distributed-chat/pkg/session"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	addr    string
	port    uint
	keyFile string
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

		var privKeyBundle identity.PrivateKeyBundle
		if err := privKeyBundle.Load(keyFile); err != nil {
			logger.Get().Fatalf("Got error reading private key file: %s", err.Error())
		}

		dbURI, err := database.MakeDBURI()
		if err != nil {
			logger.Get().Fatalf("Got error while making database URI: %s", err.Error())
		}

		query, err := database.Connect(ctx, dbURI)
		if err != nil {
			logger.Get().Fatalf("Got error while connecting to database: %s", err.Error())
		}

		address, err := privKeyBundle.Public().Address()
		if err != nil {
			logger.Get().Fatalf("Got error calculating identity address: %s", err.Error())
		}

		logger.Get().Infof("Our address is %s", address.Base32())

		// Session Manager
		mgr := session.NewSessionManager(address, &privKeyBundle)

		bindAddr := fmt.Sprintf("[%s]:%d", addr, port)
		logger.Get().Infof("Starting server on %s", bindAddr)
		tcpLn, err := net.Listen("tcp", bindAddr)
		if err != nil {
			logger.Get().Fatalf("Got error making TCP listener: %s", err.Error())
		}

		nethandle.ServeListener(ctx, tcpLn, &wg, mgr, query)

		// Socket init
		var sockLn net.Listener
		sp, err := ipcprotocol.DefaultSocketPath()
		if err != nil {
			logger.Get().Fatalf("Got error while getting socket path: %s", err.Error())
		}

		sockLn, err = net.Listen("unix", sp)
		if err != nil {
			logger.Get().Fatalf("Got error making Socket listener: %s", err.Error())
		}

		logger.Get().Infof("Starting server on socket %s", sp)
		ipchandle.ServerIpcListener(ctx, sockLn, &wg, query)

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
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.Flags().StringVarP(&addr, "address", "a", "::", "Address to listen on")
	rootCmd.Flags().UintVarP(&port, "port", "p", 1337, "Port to listen on")
	rootCmd.Flags().StringVarP(&keyFile, "keyfile", "k", "./private.key", "Private key file")
}
