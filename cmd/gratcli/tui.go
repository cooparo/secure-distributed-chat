package main

import (
	"errors"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Interactive TUI chat interface",
	Run: func(cmd *cobra.Command, args []string) {
		keyFile, err := cmd.Flags().GetString("keyfile")
		if err != nil {
			fmt.Printf("Error reading flags: %s\n", err.Error())
			os.Exit(1)
		}

		privKeyBundle := &identity.PrivateKeyBundle{}
		if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
			fmt.Println("No identity found, generating a new one...")
			privKeyBundle, err = identity.GenerateIdentity()
			if err != nil {
				fmt.Printf("Error generating identity: %s\n", err.Error())
				os.Exit(1)
			}
			if err := privKeyBundle.Save(keyFile); err != nil {
				fmt.Printf("Error saving keyfile: %s\n", err.Error())
				os.Exit(1)
			}
		} else if err := privKeyBundle.Load(keyFile); err != nil {
			fmt.Printf("Error loading keyfile %s: %s\n", keyFile, err.Error())
			os.Exit(1)
		}

		address, err := privKeyBundle.Public().Address()
		if err != nil {
			fmt.Printf("Error calculating address: %s\n", err.Error())
			os.Exit(1)
		}

		m := newModel(address)
		p := tea.NewProgram(m, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Printf("Error running TUI: %s\n", err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	tuiCmd.Flags().StringP("keyfile", "k", "./private.key", "Private key file")
}
