package command

import (
	"fmt"
	"io"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/communication"
	"github.com/cooparo/secure-distributed-chat/pkg/connection"
	"github.com/spf13/cobra"
)

var (
	bind string
)

var rootCmd = &cobra.Command{
	Use: "jbackserver",
	Short: "Background server for jchat",
	Run: func(cmd *cobra.Command, args []string) {
		s := fmt.Sprintf("Starting server on %s\n", bind)
		io.WriteString(os.Stdout, s)
		connection.StartServer(bind, communication.HandleConnection)
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
	rootCmd.Flags().StringVarP(&bind, "bind", "b", ":1337", "Address to listens on")
}

