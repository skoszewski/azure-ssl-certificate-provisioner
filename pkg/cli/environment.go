package cli

import (
	"github.com/spf13/cobra"
)

// createEnvironmentCommand creates the environment command
func (c *Commands) createEnvironmentCommand() *cobra.Command {
	var envCmd = &cobra.Command{
		Use:   "environment",
		Short: "Generate environment variable templates",
		Long:  `Generate Bash or PowerShell environment variable templates for required configuration.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Default to bash if no subcommand is specified
			c.templateGen.GenerateEnvironmentTemplate("bash")
		},
	}

	// Create bash subcommand
	bashCmd := &cobra.Command{
		Use:   "bash",
		Short: "Generate Bash environment variable template",
		Run: func(cmd *cobra.Command, args []string) {
			c.templateGen.GenerateEnvironmentTemplate("bash")
		},
	}

	// Create PowerShell subcommand
	powershellCmd := &cobra.Command{
		Use:     "powershell",
		Aliases: []string{"ps", "ps1"},
		Short:   "Generate PowerShell environment variable template",
		Run: func(cmd *cobra.Command, args []string) {
			c.templateGen.GenerateEnvironmentTemplate("powershell")
		},
	}

	envCmd.AddCommand(bashCmd)
	envCmd.AddCommand(powershellCmd)
	return envCmd
}
