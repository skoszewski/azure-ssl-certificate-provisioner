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
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")

	// configure config command
	configSetup()
	rootCmd.AddCommand(configCmd)

	// configure environment command
	envSetup()
	rootCmd.AddCommand(envCmd)
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

// setupFlagBindings configures flag bindings to viper
func setupFlagBindings(runCmd, listCmd, createSPCmd, deleteSPCmd *cobra.Command) {
	// Bind flags to viper for run command
	viper.BindPFlag("zones", runCmd.Flags().Lookup("zones"))
	viper.BindPFlag("subscription", runCmd.Flags().Lookup("subscription"))
	viper.BindPFlag("resource-group", runCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("staging", runCmd.Flags().Lookup("staging"))
	viper.BindPFlag("expire-threshold", runCmd.Flags().Lookup("expire-threshold"))
	viper.BindPFlag("email", runCmd.Flags().Lookup("email"))

	// Bind flags to viper for list command (reuse same bindings as run command)
	viper.BindPFlag("zones", listCmd.Flags().Lookup("zones"))
	viper.BindPFlag("subscription", listCmd.Flags().Lookup("subscription"))
	viper.BindPFlag("resource-group", listCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("staging", listCmd.Flags().Lookup("staging"))
	viper.BindPFlag("expire-threshold", listCmd.Flags().Lookup("expire-threshold"))
	viper.BindPFlag("email", listCmd.Flags().Lookup("email"))

	// Bind flags for create-sp command
	viper.BindPFlag("sp-name", createSPCmd.Flags().Lookup("name"))
	viper.BindPFlag("azure-tenant-id", createSPCmd.Flags().Lookup("tenant-id"))
	viper.BindPFlag("subscription", createSPCmd.Flags().Lookup("subscription-id"))
	viper.BindPFlag("resource-group", createSPCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("kv-name", createSPCmd.Flags().Lookup("kv-name"))
	viper.BindPFlag("kv-resource-group", createSPCmd.Flags().Lookup("kv-resource-group"))
	viper.BindPFlag("sp-no-roles", createSPCmd.Flags().Lookup("no-roles"))
	viper.BindPFlag("sp-use-cert-auth", createSPCmd.Flags().Lookup("use-cert-auth"))
	viper.BindPFlag("shell", createSPCmd.Flags().Lookup("shell"))

	// Bind flags for delete-service-principal command
	viper.BindPFlag("delete-sp-client-id", deleteSPCmd.Flags().Lookup("client-id"))
	viper.BindPFlag("azure-tenant-id", deleteSPCmd.Flags().Lookup("tenant-id"))
	viper.BindPFlag("subscription", deleteSPCmd.Flags().Lookup("subscription-id"))
}
