package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"azure-ssl-certificate-provisioner/internal/utilities"
)

var envCmd = &cobra.Command{
	Use:     "environment",
	Short:   "Generate environment variable templates",
	Long:    `Generate Bash or PowerShell environment variable templates for required configuration.`,
	PreRunE: envPreRunE,
	Run:     envRun,
}

var envShellTypes = []string{"bash", "powershell"}

// Validate shell value
func envPreRunE(cmd *cobra.Command, args []string) error {
	shell, err := cmd.Flags().GetString("shell")
	if err != nil {
		return err
	}

	if !slices.Contains(append(envShellTypes, ""), strings.ToLower(shell)) {
		return fmt.Errorf("invalid shell type: %s (allowed: bash, powershell)", shell)
	}

	return nil
}

func envRun(cmd *cobra.Command, args []string) {
	// Get flag values
	msiType, _ := cmd.Flags().GetString("use-msi") // TODO: Move validation logic to PreRunE
	chosenShell, _ := cmd.Flags().GetString("shell")

	// Use OS-appropriate shell if no subcommand is specified
	if chosenShell == "" {
		chosenShell = utilities.GetDefaultShell()
	}

	GenerateEnvironmentTemplate(chosenShell, msiType)
}

func envSetup(cmd *cobra.Command) {
	cmd.Flags().StringP("use-msi", "m", "", "Generate templated for MI authentication (system|user)")
	cmd.Flags().StringP("shell", "s", "", "Chosen shell type")
	cmd.RegisterFlagCompletionFunc("shell", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return envShellTypes, cobra.ShellCompDirectiveNoFileComp
	})
}
