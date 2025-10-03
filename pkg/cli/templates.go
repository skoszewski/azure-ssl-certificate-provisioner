package cli

import (
	"azure-ssl-certificate-provisioner/pkg/constants"
	"azure-ssl-certificate-provisioner/pkg/types"
	"bytes"
	"embed"
	"fmt"
	"log"
	"strings"
	"text/template"

	legoAzure "github.com/go-acme/lego/v4/providers/dns/azuredns"
	"github.com/spf13/viper"
)

type envTemplateKeyNames struct {
	Email                  string
	SubscriptionID         string
	ResourceGroupName      string
	KeyVaultURL            string
	AzureClientID          string
	AzureClientSecret      string
	AzureTenantID          string
	AzureAuthMethod        string
	MSIType                string
	MSITypeStr             string
	EmailValue             string
	SubscriptionIDValue    string
	ResourceGroupNameValue string
	KeyVaultURLValue       string
	AzureClientIDValue     string
	AzureClientSecretValue string
	AzureTenantIDValue     string
	AzureAuthMethodValue   string
}

//go:embed templates/env/*.tmpl
var envTemplates embed.FS

func getValueOrPlaceholder(key, placeholder string, spInfo *types.ServicePrincipalInfo, force bool) string {
	// Always return placeholder if force is true
	if force {
		return placeholder
	}

	if spInfo == nil {
		value := viper.GetString(key)
		if value == "" {
			return placeholder
		}
		return value
	}
	return spInfo.GetValue(key)
}

func generateEnvWithTemplate(shell, msiType string, spInfo *types.ServicePrincipalInfo, force bool) {
	envTemplate, err := envTemplates.ReadFile(fmt.Sprintf("templates/env/%s.tmpl", strings.ToLower(shell)))
	if err != nil {
		log.Fatalf("Error (internal) reading environment template: %v", err)
	}

	tmpl, err := template.New(shell).Parse(string(envTemplate))
	if err != nil {
		log.Fatalf("Error parsing environment template: %v", err)
	}

	var msiTypeStr string
	switch msiType {
	case constants.MSISystem:
		msiTypeStr = "System-assigned Managed Identity"
	case constants.MSIUser:
		msiTypeStr = "User-assigned Managed Identity"
	default:
		msiTypeStr = "Service Principal"
	}

	names := envTemplateKeyNames{
		SubscriptionID:         legoAzure.EnvSubscriptionID,
		ResourceGroupName:      constants.EnvResourceGroup,
		KeyVaultURL:            constants.EnvKeyVaultURL,
		Email:                  constants.EnvLegoEmail,
		AzureClientID:          legoAzure.EnvClientID,
		AzureClientSecret:      legoAzure.EnvClientSecret,
		AzureTenantID:          legoAzure.EnvTenantID,
		AzureAuthMethod:        legoAzure.EnvAuthMethod,
		MSIType:                msiType,
		MSITypeStr:             msiTypeStr,
		EmailValue:             getValueOrPlaceholder(constants.Email, "<your-email@example.com>", spInfo, force),
		SubscriptionIDValue:    getValueOrPlaceholder(constants.SubscriptionID, "your-subscription-id", spInfo, force),
		ResourceGroupNameValue: getValueOrPlaceholder(constants.ResourceGroupName, "your-resource-group-name", spInfo, force),
		KeyVaultURLValue:       getValueOrPlaceholder(constants.KeyVaultURL, "https://your-keyvault.vault.azure.net/", spInfo, force),
		AzureClientIDValue:     getValueOrPlaceholder(constants.AzureClientID, "your-client-id", spInfo, force),
		AzureClientSecretValue: getValueOrPlaceholder(constants.AzureClientSecret, "your-client-secret", spInfo, force),
		AzureTenantIDValue:     getValueOrPlaceholder(constants.AzureTenantID, "your-tenant-id", spInfo, force),
		AzureAuthMethodValue:   getValueOrPlaceholder(constants.AzureAuthMethod, "(none|system|user)", spInfo, force),
	}

	var output bytes.Buffer
	if err := tmpl.Execute(&output, names); err != nil {
		log.Fatalf("Error executing %s template: %v", strings.ToUpper(shell), err)
	}

	fmt.Print(output.String())
}
