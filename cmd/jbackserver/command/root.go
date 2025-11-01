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
	RunE: func(cmd *cobra.Command, args []string) (error) {
		s := fmt.Sprintf("Starting server on %s\n", bind)
		io.WriteString(os.Stdout, s)
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
	rootCmd.Flags().StringVarP(&bind, "bind", "b", ":1337", "Address to listens on")
}

