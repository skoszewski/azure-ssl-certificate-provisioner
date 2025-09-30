package cli

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/utilities"
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// utilities.LogDefault("Command execution failed: %v", err)
		os.Exit(1)
	}
}

func init() {
	// Initialize viper and configuration
	cobra.OnInitialize(initConfig)

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
	viper.BindEnv("subscription", "AZURE_SUBSCRIPTION_ID")
	viper.BindEnv("resource-group", "AZURE_RESOURCE_GROUP")
	viper.BindEnv("key-vault-url", "AZURE_KEY_VAULT_URL")
	viper.BindEnv("email", "LEGO_EMAIL")

	// Azure authentication environment variables for lego DNS provider
	viper.BindEnv("azure-client-id", "AZURE_CLIENT_ID")
	viper.BindEnv("azure-client-secret", "AZURE_CLIENT_SECRET")
	viper.BindEnv("azure-tenant-id", "AZURE_TENANT_ID")
	viper.BindEnv("azure-auth-method", "AZURE_AUTH_METHOD")
	viper.BindEnv("azure-auth-msi-timeout", "AZURE_AUTH_MSI_TIMEOUT")

	// Set defaults
	viper.SetDefault("staging", true)
	viper.SetDefault("azure-auth-method", "")
	viper.SetDefault("azure-auth-msi-timeout", "2s")
}

func initConfig() {
	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		utilities.LogVerbose("Using config file: %s", viper.ConfigFileUsed())
	} else {
		utilities.LogVerbose("No config file found, relying on environment variables and flags")
	}
}
