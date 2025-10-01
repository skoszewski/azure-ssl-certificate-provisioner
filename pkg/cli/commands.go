package cli

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/constants"
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// utilities.LogDefault("Command execution failed: %v", err)
		os.Exit(1)
	}
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
	viper.BindEnv(constants.SubscriptionID, "AZURE_SUBSCRIPTION_ID")
	viper.BindEnv(constants.ResourceGroupName, "AZURE_RESOURCE_GROUP")
	viper.BindEnv(constants.KeyVaultURL, "AZURE_KEY_VAULT_URL")
	viper.BindEnv(constants.Email, "LEGO_EMAIL")

	// Azure authentication environment variables for lego DNS provider
	viper.BindEnv(constants.AzureClientId, "AZURE_CLIENT_ID")
	viper.BindEnv(constants.AzureClientSecret, "AZURE_CLIENT_SECRET")
	viper.BindEnv(constants.AzureTenantId, "AZURE_TENANT_ID")
	viper.BindEnv(constants.AzureAuthMethod, "AZURE_AUTH_METHOD")
	viper.BindEnv(constants.AzureAuthMsiTimeout, "AZURE_AUTH_MSI_TIMEOUT")

	// Set defaults
	viper.SetDefault(constants.Staging, true)
	viper.SetDefault(constants.AzureAuthMethod, "")
	viper.SetDefault(constants.AzureAuthMsiTimeout, "2s")
	viper.SetDefault(constants.ExpireThreshold, 7)

	// Initialize viper and configuration file
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.AddConfigPath(".")
	viper.SetConfigName("config")

	if configFile != "" {
		viper.SetConfigFile(configFile)
		utilities.LogVerbose("Config file set to: %s", configFile)
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		utilities.LogVerbose("Using config file: %s", viper.ConfigFileUsed())
	} else {
		utilities.LogVerbose("No config file found, relying on environment variables and flags")
	}
}
