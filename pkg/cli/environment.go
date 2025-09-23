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
			msiType, _ := cmd.Flags().GetString("use-msi")
			c.templateGen.GenerateEnvironmentTemplate("bash", msiType)
		},
	}

	// Add --use-msi flag to the main command
	envCmd.PersistentFlags().String("use-msi", "", "Generate template for Managed Identity authentication (system|user)")

	// Create bash subcommand
	bashCmd := &cobra.Command{
		Use:   "bash",
		Short: "Generate Bash environment variable template",
		Run: func(cmd *cobra.Command, args []string) {
			msiType, _ := cmd.Flags().GetString("use-msi")
			c.templateGen.GenerateEnvironmentTemplate("bash", msiType)
		},
	}

	// Create PowerShell subcommand
	powershellCmd := &cobra.Command{
		Use:     "powershell",
		Aliases: []string{"ps", "ps1"},
		Short:   "Generate PowerShell environment variable template",
		Run: func(cmd *cobra.Command, args []string) {
			msiType, _ := cmd.Flags().GetString("use-msi")
			c.templateGen.GenerateEnvironmentTemplate("powershell", msiType)
		},
	}

	envCmd.AddCommand(bashCmd)
	envCmd.AddCommand(powershellCmd)
	return envCmd
}
