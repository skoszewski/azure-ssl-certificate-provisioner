package cli

import (
	"azure-ssl-certificate-provisioner/internal/utilities"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Define the root command
var rootCmd = &cobra.Command{
	Use:   "azure-ssl-certificate-provisioner",
	Short: "Automatically provision SSL certificates from Let's Encrypt for Azure DNS zones",
	Long: `Azure SSL Certificate Provisioner scans Azure DNS zones for records marked with
ACME metadata and automatically provisions SSL certificates using Let's Encrypt,
storing them in Azure Key Vault.`,
	PersistentPreRun: rootSetup, // Call setup on pre-run.
}

// Setup root command.
func rootSetup(cmd *cobra.Command, args []string) {
	// Global verbose affetcs logging.
	// It must be initilized early
	verbose := viper.GetBool("verbose")
	utilities.SetVerbose(verbose)
}
