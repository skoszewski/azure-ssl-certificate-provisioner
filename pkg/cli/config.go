package cli

import (
	"azure-ssl-certificate-provisioner/internal/utilities"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate configuration file templates",
	Long: `Generate configuration file templates in different formats.
Supported formats: json, toml, yaml (default: yaml)
For environment variables, use: azure-ssl-certificate-provisioner environment`,
	Args: cobra.MaximumNArgs(1),
	Run:  configRun,
}

func configRun(cmd *cobra.Command, args []string) {
	format, _ := cmd.Flags().GetString("format")
	utilities.LogVerbose("The chosen format is %v", format)
	GenerateConfigTemplate(format)
}

func configSetup(cmd *cobra.Command) {
	cmd.Flags().StringP("format", "f", "yaml", "config file format")
}
