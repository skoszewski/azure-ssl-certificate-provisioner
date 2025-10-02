package cli

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// utilities.LogDefault("Command execution failed: %v", err)
		os.Exit(1)
	}
}

// Helper that simplifies binding Viper keys to Cobra flags
func BindPFlag(cmd *cobra.Command, key string) {
	viper.BindPFlag(key, cmd.Flags().Lookup(key))
}

func init() {
	// configure root command
	rootSetup(rootCmd)

	// configure config command
	configSetup(configCmd)
	rootCmd.AddCommand(configCmd)

	// configure environment command
	envSetup(envCmd)
	rootCmd.AddCommand(envCmd)

	// configure list command
	listCmdSetup(listCmd)
	rootCmd.AddCommand(listCmd)

	// configure run command
	runCmdSetup(runCmd)
	rootCmd.AddCommand(runCmd)

	// configure create a Service Principal command
	createSPCmdSetup(createSPCmd)
	rootCmd.AddCommand(createSPCmd)

	// configure delete the Service Principal command
	deleteSPCmdSetup(deleteSPCmd)
	rootCmd.AddCommand(deleteSPCmd)
}
