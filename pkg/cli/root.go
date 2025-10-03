package cli

import (
	"azure-ssl-certificate-provisioner/pkg/constants"
	utilities "azure-ssl-certificate-provisioner/pkg/utils"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Define a variable to hold the config file path
var configFile string = "config"

// Define the root command
var rootCmd = &cobra.Command{
	Use:   "azure-ssl-certificate-provisioner",
	Short: "Automatically provision SSL certificates from Let's Encrypt for Azure DNS zones",
	Long: `Azure SSL Certificate Provisioner scans Azure DNS zones for records marked with
ACME metadata and automatically provisions SSL certificates using Let's Encrypt,
storing them in Azure Key Vault.`,
}

func rootSetup(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(utilities.GetVerbosePtr(), constants.Verbose, "v", false, "Enable verbose output")
	cmd.PersistentFlags().StringVar(&configFile, constants.ConfigFile, "", fmt.Sprintf("Config file (default is %s.%s in the current directory)", constants.ConfigFile, constants.YAML))

	viper.BindPFlag(constants.ConfigFile, cmd.Flags().Lookup(constants.ConfigFile))
	viper.BindEnv(constants.ConfigFile, constants.EnvConfigFile)
}
