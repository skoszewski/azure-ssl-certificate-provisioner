package cli

import (
	"azure-ssl-certificate-provisioner/pkg/constants"
	"azure-ssl-certificate-provisioner/pkg/utils"
	"bytes"
	"embed"
	"fmt"
	"log"
	"slices"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

type configTemplateKeyNames struct {
	SubscriptionID    string
	ResourceGroupName string
	KeyVaultURL       string
	Email             string
	Staging           string
	ExpireThreshold   string
	AzureClientID     string
	AzureClientSecret string
	AzureTenantID     string
	Zones             string
}

//go:embed templates/config/*.tmpl
var configTemplates embed.FS

var availableConfigFormats = []string{constants.JSON, constants.TOML, constants.YAML}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate configuration file templates",
	Long: fmt.Sprintf(`Generate configuration file templates in different formats.
Supported formats: %s (default: %s)`, strings.Join(availableConfigFormats, ", "), constants.YAML),
	RunE: configCmdRunE,
}

func configCmdRunE(cmd *cobra.Command, args []string) error {

	format, _ := cmd.Flags().GetString(constants.Format)
	utils.LogVerbose("The chosen format is %v", format)

	if slices.Contains(availableConfigFormats, format) == false {
		// Utilize cobra's error handling
		return fmt.Errorf("Unsupported format '%s'. Supported formats: %s", format, strings.Join(availableConfigFormats, ", "))
	}

	yamlTemplate, err := configTemplates.ReadFile(fmt.Sprintf("templates/config/%s.tmpl", strings.ToLower(format)))
	if err != nil {
		log.Fatalf("Error (internal) reading %s template: %v", format, err)
	}

	tmpl, err := template.New(format).Parse(string(yamlTemplate))
	if err != nil {
		log.Fatalf("Error parsing YAML template: %v", err)
	}

	names := configTemplateKeyNames{
		SubscriptionID:    constants.SubscriptionID,
		ResourceGroupName: constants.ResourceGroupName,
		KeyVaultURL:       constants.KeyVaultURL,
		Email:             constants.Email,
		Staging:           constants.Staging,
		ExpireThreshold:   constants.ExpireThreshold,
		AzureClientID:     constants.AzureClientID,
		AzureClientSecret: constants.AzureClientSecret,
		AzureTenantID:     constants.AzureTenantID,
		Zones:             constants.Zones,
	}

	var output bytes.Buffer
	if err := tmpl.Execute(&output, names); err != nil {
		log.Fatalf("Error executing %s template: %v", strings.ToUpper(format), err)
	}

	fmt.Print(output.String())

	return nil
}

func configSetup(cmd *cobra.Command) {
	cmd.Flags().StringP(constants.Format, "f", constants.YAML, "config file format")
}
