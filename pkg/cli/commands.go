package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/pkg/config"
)

// Commands holds all CLI commands
type Commands struct {
	templateGen *TemplateGenerator
}

// NewCommands creates a new commands instance
func NewCommands() *Commands {
	return &Commands{
		templateGen: NewTemplateGenerator(),
	}
}

// CreateRootCommand creates the root cobra command
func (c *Commands) CreateRootCommand() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "azure-ssl-certificate-provisioner",
		Short: "Automatically provision SSL certificates from Let's Encrypt for Azure DNS zones",
		Long: `Azure SSL Certificate Provisioner scans Azure DNS zones for records marked with 
ACME metadata and automatically provisions SSL certificates using Let's Encrypt, 
storing them in Azure Key Vault.`,
	}

	// Create subcommands
	runCmd := c.createRunCommand()
	listCmd := c.createListCommand()
	envCmd := c.createEnvironmentCommand()
	createSPCmd := c.createServicePrincipalCommand()

	// Configure flag bindings
	c.setupFlagBindings(runCmd, listCmd, createSPCmd)

	// Add subcommands to root command
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(createSPCmd)

	return rootCmd
}

// setupFlagBindings configures flag bindings to viper
func (c *Commands) setupFlagBindings(runCmd, listCmd, createSPCmd *cobra.Command) {
	// Setup viper configuration first (environment variable bindings)
	config.SetupViper()

	// Bind flags to viper for run command
	viper.BindPFlag("zones", runCmd.Flags().Lookup("zones"))
	viper.BindPFlag("subscription", runCmd.Flags().Lookup("subscription"))
	viper.BindPFlag("resource-group", runCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("staging", runCmd.Flags().Lookup("staging"))
	viper.BindPFlag("expire-threshold", runCmd.Flags().Lookup("expire-threshold"))
	viper.BindPFlag("email", runCmd.Flags().Lookup("email"))

	// Bind flags to viper for list command (same as run command)
	viper.BindPFlag("list-zones", listCmd.Flags().Lookup("zones"))
	viper.BindPFlag("list-subscription", listCmd.Flags().Lookup("subscription"))
	viper.BindPFlag("list-resource-group", listCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("list-staging", listCmd.Flags().Lookup("staging"))
	viper.BindPFlag("list-expire-threshold", listCmd.Flags().Lookup("expire-threshold"))
	viper.BindPFlag("list-email", listCmd.Flags().Lookup("email"))

	// Bind flags for create-service-principal command (using sp- prefix to avoid conflicts)
	viper.BindPFlag("sp-name", createSPCmd.Flags().Lookup("name"))
	viper.BindPFlag("sp-tenant-id", createSPCmd.Flags().Lookup("tenant-id"))
	viper.BindPFlag("sp-subscription-id", createSPCmd.Flags().Lookup("subscription-id"))
	viper.BindPFlag("sp-resource-group", createSPCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("sp-kv-name", createSPCmd.Flags().Lookup("kv-name"))
	viper.BindPFlag("sp-kv-resource-group", createSPCmd.Flags().Lookup("kv-resource-group"))
	viper.BindPFlag("sp-no-roles", createSPCmd.Flags().Lookup("no-roles"))
	viper.BindPFlag("sp-use-cert-auth", createSPCmd.Flags().Lookup("use-cert-auth"))
	viper.BindPFlag("sp-shell", createSPCmd.Flags().Lookup("shell"))
}
