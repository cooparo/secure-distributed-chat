package command

import (
	"fmt"
	"os"

	"github.com/cooparo/secure-distributed-chat/cmd/jchat/command/client"
	"github.com/cooparo/secure-distributed-chat/cmd/jchat/command/server"
	"github.com/spf13/cobra"
)


var rootCmd = &cobra.Command{
	Use: "jchat",
	Short: "Chat",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
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
	rootCmd.AddCommand(server.ServerCmd)
	rootCmd.AddCommand(client.ClientCmd)
}
