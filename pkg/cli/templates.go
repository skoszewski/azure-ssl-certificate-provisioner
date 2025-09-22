package cli

import (
	"fmt"
	"log"
	"strings"

	"azure-ssl-certificate-provisioner/internal/types"
)

// TemplateGenerator handles generating environment variable templates
type TemplateGenerator struct{}

// NewTemplateGenerator creates a new template generator
func NewTemplateGenerator() *TemplateGenerator {
	return &TemplateGenerator{}
}

// GenerateEnvironmentTemplate generates environment variable templates
func (g *TemplateGenerator) GenerateEnvironmentTemplate(shell string) {
	switch strings.ToLower(shell) {
	case "powershell", "ps1":
		g.generatePowerShellTemplate()
	case "bash", "sh":
		g.generateBashTemplate()
	default:
		log.Printf("Unsupported shell type: shell=%s, supported=bash,powershell", shell)
		g.generateBashTemplate()
	}
}

func (g *TemplateGenerator) generateBashTemplate() {
	fmt.Println("# ACME account email for Let's Encrypt registration")
	fmt.Println("export LEGO_EMAIL=\"your-email@example.com\"")
	fmt.Println("# Azure subscription and resource group")
	fmt.Println("export AZURE_SUBSCRIPTION_ID=\"your-azure-subscription-id\"")
	fmt.Println("export AZURE_RESOURCE_GROUP=\"your-resource-group-name\"")
	fmt.Println("# Azure Key Vault for certificate storage")
	fmt.Println("export AZURE_KEY_VAULT_URL=\"https://your-keyvault.vault.azure.net/\"")
	fmt.Println("# Azure authentication (Service Principal)")
	fmt.Println("export AZURE_CLIENT_ID=\"your-service-principal-client-id\"")
	fmt.Println("export AZURE_CLIENT_SECRET=\"your-service-principal-client-secret\"")
	fmt.Println("export AZURE_TENANT_ID=\"your-azure-tenant-id\"")
}

func (g *TemplateGenerator) generatePowerShellTemplate() {
	fmt.Println("# ACME account email for Let's Encrypt registration")
	fmt.Println("$env:LEGO_EMAIL = \"your-email@example.com\"")
	fmt.Println("# Azure subscription and resource group")
	fmt.Println("$env:AZURE_SUBSCRIPTION_ID = \"your-azure-subscription-id\"")
	fmt.Println("$env:AZURE_RESOURCE_GROUP = \"your-resource-group-name\"")
	fmt.Println("# Azure Key Vault for certificate storage")
	fmt.Println("$env:AZURE_KEY_VAULT_URL = \"https://your-keyvault.vault.azure.net/\"")
	fmt.Println("# Azure authentication (Service Principal)")
	fmt.Println("$env:AZURE_CLIENT_ID = \"your-service-principal-client-id\"")
	fmt.Println("$env:AZURE_CLIENT_SECRET = \"your-service-principal-client-secret\"")
	fmt.Println("$env:AZURE_TENANT_ID = \"your-azure-tenant-id\"")
}

// GenerateServicePrincipalTemplate generates environment variable templates with actual SP values
func (g *TemplateGenerator) GenerateServicePrincipalTemplate(spInfo *types.ServicePrincipalInfo, shell, keyVaultName, keyVaultResourceGroup string) {
	switch strings.ToLower(shell) {
	case "powershell", "ps1":
		g.generateServicePrincipalPowerShellTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	case "bash", "sh":
		g.generateServicePrincipalBashTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	default:
		log.Printf("Unsupported shell type: shell=%s, using=bash", shell)
		g.generateServicePrincipalBashTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	}
}

func (g *TemplateGenerator) generateServicePrincipalBashTemplate(spInfo *types.ServicePrincipalInfo, keyVaultName, keyVaultResourceGroup string) {
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
	fmt.Printf("export AZURE_CLIENT_SECRET=\"%s\"\n", spInfo.ClientSecret)
}

func (g *TemplateGenerator) generateServicePrincipalPowerShellTemplate(spInfo *types.ServicePrincipalInfo, keyVaultName, keyVaultResourceGroup string) {
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
	fmt.Printf("$env:AZURE_CLIENT_SECRET = \"%s\"\n", spInfo.ClientSecret)
}
