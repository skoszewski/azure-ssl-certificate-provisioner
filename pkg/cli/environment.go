package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/constants"
)

var envCmd = &cobra.Command{
	Use:     "environment",
	Short:   "Generate environment variable templates",
	Long:    `Generate Bash or PowerShell environment variable templates for required configuration.`,
	PreRunE: envPreRunE,
	Run:     envRun,
}

var envShellTypes = []string{constants.Bash, constants.PowerShell}

// Validate shell value
func envPreRunE(cmd *cobra.Command, args []string) error {
	shell, err := cmd.Flags().GetString(constants.Shell)
	if err != nil {
		return err
	}

	if !slices.Contains(append(envShellTypes, ""), strings.ToLower(shell)) {
		return fmt.Errorf("invalid shell type: %s (allowed: %s)", shell, strings.Join(envShellTypes, ", "))
	}

	return nil
}

func envRun(cmd *cobra.Command, args []string) {
	// Get flag values
	msiType, _ := cmd.Flags().GetString(constants.UseMSI)
	chosenShell, _ := cmd.Flags().GetString(constants.Shell)

	// Use OS-appropriate shell if no subcommand is specified
	if chosenShell == "" {
		chosenShell = utilities.GetDefaultShell()
	}

	generateEnvWithTemplate(chosenShell, msiType, true)
}

func envSetup(cmd *cobra.Command) {
	cmd.Flags().StringP(constants.UseMSI, "m", "", "Generate templated for MI authentication (system|user)")
	cmd.Flags().StringP(constants.Shell, "s", "", "Chosen shell type")
	cmd.RegisterFlagCompletionFunc(constants.Shell, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return envShellTypes, cobra.ShellCompDirectiveNoFileComp
	})
}
