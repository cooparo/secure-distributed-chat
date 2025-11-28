package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cooparo/secure-distributed-chat/pkg/identity"
	"github.com/spf13/cobra"
)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Interact with your Identity",
	Run: func(cmd *cobra.Command, args []string) {
		var privKeyBundle *identity.PrivateKeyBundle
		var address identity.IdentityAddress
		var keyFileExists bool

		generate, err := cmd.Flags().GetBool("generate")
		if err != nil {
			fmt.Printf("Got error reading flags: %s\n", err.Error())
			os.Exit(1)
		}
		overwriteKeyFile, err := cmd.Flags().GetBool("overwrite-keyfile")
		if err != nil {
			fmt.Printf("Got error reading flags: %s\n", err.Error())
			os.Exit(1)
		}
		keyFile, err := cmd.Flags().GetString("keyfile")
		if err != nil {
			fmt.Printf("Got error reading flags: %s\n", err.Error())
			os.Exit(1)
		}

		_, err = os.Stat(keyFile)
		keyFileExists = !errors.Is(err, os.ErrNotExist)

		if generate {
			fmt.Print("Generating new identity...\n")
			if !overwriteKeyFile && keyFileExists {
				message := "Keyfile %s already exists, not overwriting\n" +
					"Use '--overwrite-keyfile' to disable this check\n"

				fmt.Printf(message, keyFile)
				os.Exit(1)
			}

			privKeyBundle, err = identity.GenerateIdentity()
			if err != nil {
				fmt.Printf("Got error while generating identity: %s\n", err.Error())
				os.Exit(1)
			}
			if err := privKeyBundle.Save(keyFile); err != nil {
				fmt.Printf("Got error while saving key file: %s\n", err.Error())
				os.Exit(1)
			}
		} else {
			if !keyFileExists {
				message := "Keyfile %s doesn't exist\n" +
					"Use '--generate' or '-g' to generate it\n"
				fmt.Printf(message, keyFile)
				os.Exit(1)
			}
			privKeyBundle = &identity.PrivateKeyBundle{}
			if err := privKeyBundle.Load(keyFile); err != nil {
				fmt.Printf("Got error while loading key file: %s\n", err.Error())
				os.Exit(1)
			}
		}

		address, err = privKeyBundle.Public().Address()
		if err != nil {
			fmt.Printf("Got error while calculating address: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("Your address is: %s\n", address.Base32())
	},
}

func init() {
	identityCmd.Flags().BoolP("generate", "g", false, "Generate the identity")
	identityCmd.Flags().Bool("overwrite-keyfile", false, "Overwrite an existing keyfile when generating")
	identityCmd.Flags().StringP("keyfile", "k", "./private.key", "Private key file")
}
