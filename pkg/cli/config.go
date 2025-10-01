package cli

import (
	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/constants"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var availableConfigFormats = []string{constants.JSON, constants.TOML, constants.YAML}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate configuration file templates",
	Long: fmt.Sprintf(`Generate configuration file templates in different formats.
Supported formats: %s (default: %s)
For environment variables, use: %s`, strings.Join(availableConfigFormats, ", "), constants.YAML, constants.CommandName),
	Run: configRun,
}

func configRun(cmd *cobra.Command, args []string) {
	format, _ := cmd.Flags().GetString(constants.Format)
	utilities.LogVerbose("The chosen format is %v", format)
	GenerateConfigTemplate(format)
}

func configSetup(cmd *cobra.Command) {
	cmd.Flags().StringP(constants.Format, "f", constants.YAML, "config file format")
}

// GenerateConfigTemplate generates configuration templates in different formats
func GenerateConfigTemplate(format string) {
	switch format {
	case constants.JSON:
		generateConfigWithTemplate(constants.JSON)
	case constants.TOML:
		generateConfigWithTemplate(constants.TOML)
	case constants.YAML:
		generateConfigWithTemplate(constants.YAML)
	default:
		fmt.Printf("Error: Unsupported format '%s'. Supported formats: %s\n", format, strings.Join(availableConfigFormats, ", "))
		fmt.Printf("For environment variables, use: %s environment\n", constants.CommandName)
		return
	}
}
