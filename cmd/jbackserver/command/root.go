package command

import (
	"fmt"
	"io"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/communication"
	"github.com/cooparo/secure-distributed-chat/pkg/connection"
	"github.com/cooparo/secure-distributed-chat/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	bind string
)

var rootCmd = &cobra.Command{
	Use: "jbackserver",
	Short: "Background server for jchat",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Init(verbose)
	},
	RunE: func(cmd *cobra.Command, args []string) (error) {
		s := fmt.Sprintf("Starting server on %s", bind)
		logger.Get().Info(s)
		err := connection.StartServer(bind, communication.HandleConnection)
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
	rootCmd.Flags().StringVarP(&bind, "bind", "b", ":1337", "Address to listens on")
}

