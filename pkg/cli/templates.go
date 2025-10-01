package cli

import (
	"azure-ssl-certificate-provisioner/internal/types"
	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/constants"
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
	if spInfo == nil {
		value := viper.GetString(key)
		if value == "" || force { // If force is true, always return placeholder
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
		SubscriptionID:         constants.EnvAzureSubscriptionId,
		ResourceGroupName:      constants.EnvResourceGroup,
		KeyVaultURL:            constants.EnvAzureKeyVaultURL,
		Email:                  constants.EnvLegoEmail,
		AzureClientID:          constants.EnvAzureClientId,
		AzureClientSecret:      constants.EnvAzureClientSecret,
		AzureTenantID:          constants.EnvAzureTenantId,
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

// GenerateServicePrincipalTemplate generates environment variable templates with actual SP values
func GenerateServicePrincipalTemplate(spInfo *types.ServicePrincipalInfo, shell, keyVaultName, keyVaultResourceGroup string) {
	switch strings.ToLower(shell) {
	case constants.PowerShell, "ps1":
		generateServicePrincipalPowerShellTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	case constants.Bash, "sh":
		generateServicePrincipalBashTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	default:
		utilities.LogDefault("Unsupported shell type: shell=%s, using=%s", shell, constants.Bash)
		generateServicePrincipalBashTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	}
}

func generateServicePrincipalBashTemplate(spInfo *types.ServicePrincipalInfo, keyVaultName, keyVaultResourceGroup string) {
	fmt.Println("export LEGO_EMAIL=\"your-email@example.com\"")
	fmt.Printf("export AZURE_SUBSCRIPTION_ID=\"%s\"\n", spInfo.SubscriptionID)
	fmt.Printf("export AZURE_TENANT_ID=\"%s\"\n", spInfo.TenantID)
	if keyVaultResourceGroup != "" {
		fmt.Printf("export AZURE_RESOURCE_GROUP=\"%s\"\n", keyVaultResourceGroup)
	} else {
		fmt.Println("export AZURE_RESOURCE_GROUP=\"your-resource-group-name\"")
	}
	if keyVaultName != "" {
		fmt.Printf("export AZURE_KEY_VAULT_URL=\"https://%s.vault.azure.net/\"\n", keyVaultName)
	} else {
		fmt.Println("export AZURE_KEY_VAULT_URL=\"https://your-keyvault.vault.azure.net/\"")
	}
	fmt.Printf("export AZURE_CLIENT_ID=\"%s\"\n", spInfo.ClientID)

	if spInfo.UseCertAuth {
		fmt.Printf("export AZURE_CLIENT_CERTIFICATE_PATH=\"%s.crt\"\n", spInfo.ClientID)
		fmt.Printf("export AZURE_CLIENT_CERTIFICATE_PASSWORD=\"\"\n")
	} else {
		fmt.Printf("export AZURE_CLIENT_SECRET=\"%s\"\n", spInfo.ClientSecret)
	}
}

func generateServicePrincipalPowerShellTemplate(spInfo *types.ServicePrincipalInfo, keyVaultName, keyVaultResourceGroup string) {
	fmt.Println("$env:LEGO_EMAIL = \"your-email@example.com\"")
	fmt.Printf("$env:AZURE_SUBSCRIPTION_ID = \"%s\"\n", spInfo.SubscriptionID)
	fmt.Printf("$env:AZURE_TENANT_ID = \"%s\"\n", spInfo.TenantID)
	if keyVaultResourceGroup != "" {
		fmt.Printf("$env:AZURE_RESOURCE_GROUP = \"%s\"\n", keyVaultResourceGroup)
	} else {
		fmt.Println("$env:AZURE_RESOURCE_GROUP = \"your-resource-group-name\"")
	}
	if keyVaultName != "" {
		fmt.Printf("$env:AZURE_KEY_VAULT_URL = \"https://%s.vault.azure.net/\"\n", keyVaultName)
	} else {
		fmt.Println("$env:AZURE_KEY_VAULT_URL = \"https://your-keyvault.vault.azure.net/\"")
	}
	fmt.Printf("$env:AZURE_CLIENT_ID = \"%s\"\n", spInfo.ClientID)

	if spInfo.UseCertAuth {
		fmt.Printf("$env:AZURE_CLIENT_CERTIFICATE_PATH = \"%s.crt\"\n", spInfo.ClientID)
		fmt.Printf("$env:AZURE_CLIENT_CERTIFICATE_PASSWORD = \"\"\n")
	} else {
		fmt.Printf("$env:AZURE_CLIENT_SECRET = \"%s\"\n", spInfo.ClientSecret)
	}
}

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
	Name              string
	KeyVaultName      string
	KeyVaultRG        string
	NoRoles           string
	UseCertAuth       string
	Shell             string
}

//go:embed templates/config/*.tmpl
var configTemplates embed.FS

func generateConfigWithTemplate(format string) {
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
		Name:              constants.Name,
		KeyVaultName:      constants.KeyVaultName,
		KeyVaultRG:        constants.KeyVaultRG,
		NoRoles:           constants.NoRoles,
		UseCertAuth:       constants.UseCertAuth,
		Shell:             constants.Shell,
	}

	var output bytes.Buffer
	if err := tmpl.Execute(&output, names); err != nil {
		log.Fatalf("Error executing %s template: %v", strings.ToUpper(format), err)
	}

	fmt.Print(output.String())
}
