package server

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/connection"
	"github.com/spf13/cobra"
)

var (
	bind string
)

var ServerCmd = &cobra.Command{
	Use: "server",
	Short: "Start a server",
	Run: func(cmd *cobra.Command, args []string) {
		s := fmt.Sprintf("Starting server on %s\n", bind)
		io.WriteString(os.Stdout, s)
		connection.StartServer(bind, func(c net.Conn) {
			s := fmt.Sprintf("Connection from %s\n", c.RemoteAddr().String())
			io.WriteString(os.Stdout, s)
			c.Close()
		})
	},
}

func init()  {
	ServerCmd.Flags().StringVarP(&bind, "bind", "b", ":1337", "Address to listn on")
}
