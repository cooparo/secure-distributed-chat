package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gratcli",
	Short: "Grat CLI interface",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: make it communicate with IPC
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

func init() {
	rootCmd.AddCommand(identityCmd)
}
