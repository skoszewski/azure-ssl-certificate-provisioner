package main

import (
	"log"

	"azure-ssl-certificate-provisioner/pkg/cli"
)

func main() {
	commands := cli.NewCommands()
	rootCmd := commands.CreateRootCommand()

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Command execution failed: %v", err)
	}
}
