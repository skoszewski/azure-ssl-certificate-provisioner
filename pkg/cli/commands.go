package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	createConfigCmd := c.createConfigCommand()
	createSPCmd := c.createSPCommand()
	deleteSPCmd := c.createDeleteServicePrincipalCommand()

	// Configure flag bindings
	c.setupFlagBindings(runCmd, listCmd, createSPCmd, deleteSPCmd)

	// Add subcommands to root command
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(createConfigCmd)
	rootCmd.AddCommand(createSPCmd)
	rootCmd.AddCommand(deleteSPCmd)

	return rootCmd
}

// setupFlagBindings configures flag bindings to viper
func (c *Commands) setupFlagBindings(runCmd, listCmd, createSPCmd, deleteSPCmd *cobra.Command) {
	// Note: Viper setup is now done lazily in each command that needs it

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
