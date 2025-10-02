package cli

import (
	"os"

	"azure-ssl-certificate-provisioner/pkg/constants"

	legoAzure "github.com/go-acme/lego/v4/providers/dns/azuredns"
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

	// Bind Viper keys to environment variables
	viper.BindEnv(constants.SubscriptionID, legoAzure.EnvSubscriptionID)
	viper.BindEnv(constants.ResourceGroupName, constants.EnvResourceGroup)
	viper.BindEnv(constants.KeyVaultURL, constants.EnvKeyVaultURL)
	viper.BindEnv(constants.Email, constants.EnvLegoEmail)

	// Azure authentication environment variables for lego DNS provider
	viper.BindEnv(constants.AzureClientID, legoAzure.EnvClientID)
	viper.BindEnv(constants.AzureClientSecret, legoAzure.EnvClientSecret)
	viper.BindEnv(constants.AzureTenantID, legoAzure.EnvTenantID)
	viper.BindEnv(constants.AzureAuthMethod, legoAzure.EnvAuthMethod)
	viper.BindEnv(constants.AzureAuthMsiTimeout, legoAzure.EnvAuthMSITimeout)

	// Set defaults
	viper.SetDefault(constants.Staging, true)
	viper.SetDefault(constants.AzureAuthMethod, "")
	viper.SetDefault(constants.AzureAuthMsiTimeout, "2s")
	viper.SetDefault(constants.ExpireThreshold, 7)
}
