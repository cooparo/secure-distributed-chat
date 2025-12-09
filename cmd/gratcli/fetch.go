package main

import (
	"github.com/spf13/cobra"
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch messages",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: fetch new message from server
	},
}

func init() {}
