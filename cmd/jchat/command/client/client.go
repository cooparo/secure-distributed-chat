package client

import "github.com/spf13/cobra"

var ClientCmd = &cobra.Command{
	Use: "client",
	Short: "Client",
	Run: func(cmd *cobra.Command, args []string) {},
}
