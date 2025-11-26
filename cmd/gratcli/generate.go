package main

import (
	"fmt"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/spf13/cobra"
)

var (
	identityGenerate bool
	identityKeyFile  string
)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Interact with your Identity",
	Run: func(cmd *cobra.Command, args []string) {
		var privKeyBundle identity.PrivateKeyBundle
		var address identity.IdentityAddress

		if identityGenerate {
			addr, privKeyBundle, err := identity.GenerateIdentity()
			if err != nil {
				fmt.Printf("Got error while generating identity: %s\n", err.Error())
				os.Exit(1)
			}
			address = addr
			if err := privKeyBundle.Save(identityKeyFile); err != nil {
				fmt.Printf("Got error while saving key file: %s\n", err.Error())
				os.Exit(1)
			}
		} else {
			if err := privKeyBundle.Load(identityKeyFile); err != nil {
				fmt.Printf("Got error while loading key file: %s\n", err.Error())
				os.Exit(1)
			}
			addr, err := privKeyBundle.Public().Address()
			if err != nil {
				fmt.Printf("Got error while calculating address: %s\n", err.Error())
				os.Exit(1)
			}
			address = addr
		}

		fmt.Printf("Your address is: %s\n", address.Base32())
	},
}

func init() {
	identityCmd.Flags().BoolVarP(&identityGenerate, "generate", "g", false, "Generate the identity")
	identityCmd.Flags().StringVarP(&identityKeyFile, "keyfile", "k", "./private.key", "Private key file")
}
