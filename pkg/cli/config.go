package cli

import (
	"github.com/spf13/cobra"
)

// createConfigCommand creates the config command
func (c *Commands) createConfigCommand() *cobra.Command {
	var configCmd = &cobra.Command{
		Use:   "config [format]",
		Short: "Generate configuration file templates",
		Long: `Generate configuration file templates in different formats.
Supported formats: json, toml, yaml (default: yaml)
For environment variables, use: azure-ssl-certificate-provisioner environment`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			format := "yaml"
			if len(args) > 0 {
				format = args[0]
			}
			c.templateGen.GenerateConfigTemplate(format)
		},
	}

	return configCmd
}
