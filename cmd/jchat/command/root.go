package command

import (
	"fmt"
	"io"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/connection"
	"github.com/cooparo/secure-distributed-chat/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	address string
)

var rootCmd = &cobra.Command{
	Use: "jchat",
	Short: "Chat",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Init(verbose)
	},
	RunE: func(cmd *cobra.Command, args []string) (error) {
		s := fmt.Sprintf("Connecting to %s", address)
		io.WriteString(os.Stdout, s)
		err := connection.ConnectToServer(address)
		if err != nil {
			return err
		}
		return nil
	},
}

func Execute()  {
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
