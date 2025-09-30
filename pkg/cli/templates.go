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
func (g *TemplateGenerator) GenerateEnvironmentTemplate(shell string, msiType string) {
	isUserMSI := msiType == "user"

	switch strings.ToLower(shell) {
	case "powershell", "ps1":
		if msiType == "system" || msiType == "user" {
			g.generateMSIPowerShellTemplate(isUserMSI)
		} else {
			g.generatePowerShellTemplate()
		}
	case "bash", "sh":
		if msiType == "system" || msiType == "user" {
			g.generateMSIBashTemplate(isUserMSI)
		} else {
			g.generateBashTemplate()
		}
	default:
		log.Printf("Unsupported shell type: shell=%s, supported=bash,powershell", shell)
		if msiType == "system" || msiType == "user" {
			g.generateMSIBashTemplate(isUserMSI)
		} else {
			g.generateBashTemplate()
		}
	}
}

func (g *TemplateGenerator) generateBashTemplate() {
	fmt.Print(`# ACME account email for Let's Encrypt registration
export LEGO_EMAIL="your-email@example.com"
# Azure subscription and resource group
export AZURE_SUBSCRIPTION_ID="your-azure-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group-name"
# Azure Key Vault for certificate storage
export AZURE_KEY_VAULT_URL="https://your-keyvault.vault.azure.net/"
# Azure authentication (Service Principal)
export AZURE_CLIENT_ID="your-service-principal-client-id"
export AZURE_CLIENT_SECRET="your-service-principal-client-secret"
export AZURE_TENANT_ID="your-azure-tenant-id"`)
}

func (g *TemplateGenerator) generatePowerShellTemplate() {
	fmt.Print(`# ACME account email for Let's Encrypt registration
$env:LEGO_EMAIL = "your-email@example.com"
# Azure subscription and resource group
$env:AZURE_SUBSCRIPTION_ID = "your-azure-subscription-id"
$env:AZURE_RESOURCE_GROUP = "your-resource-group-name"
# Azure Key Vault for certificate storage
$env:AZURE_KEY_VAULT_URL = "https://your-keyvault.vault.azure.net/"
# Azure authentication (Service Principal)
$env:AZURE_CLIENT_ID = "your-service-principal-client-id"
$env:AZURE_CLIENT_SECRET = "your-service-principal-client-secret"
$env:AZURE_TENANT_ID = "your-azure-tenant-id"`)
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

	if spInfo.UseCertAuth {
		fmt.Printf("export AZURE_CLIENT_CERTIFICATE_PATH=\"%s.crt\"\n", spInfo.ClientID)
		fmt.Printf("export AZURE_CLIENT_CERTIFICATE_PASSWORD=\"\"\n")
	} else {
		fmt.Printf("export AZURE_CLIENT_SECRET=\"%s\"\n", spInfo.ClientSecret)
	}
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

	if spInfo.UseCertAuth {
		fmt.Printf("$env:AZURE_CLIENT_CERTIFICATE_PATH = \"%s.crt\"\n", spInfo.ClientID)
		fmt.Printf("$env:AZURE_CLIENT_CERTIFICATE_PASSWORD = \"\"\n")
	} else {
		fmt.Printf("$env:AZURE_CLIENT_SECRET = \"%s\"\n", spInfo.ClientSecret)
	}
}

// MSI template methods
func (g *TemplateGenerator) generateMSIBashTemplate(isUserMSI bool) {
	fmt.Print(`# ACME account email for Let's Encrypt registration
export LEGO_EMAIL="your-email@example.com"
# Azure subscription and resource group
export AZURE_SUBSCRIPTION_ID="your-azure-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group-name"
# Azure Key Vault for certificate storage
export AZURE_KEY_VAULT_URL="https://your-keyvault.vault.azure.net/"
# Azure authentication (Managed Identity)
export AZURE_AUTH_METHOD="msi"`)
	if isUserMSI {
		fmt.Print("\nexport AZURE_CLIENT_ID=\"your-user-assigned-msi-client-id\"")
	}
}

func (g *TemplateGenerator) generateMSIPowerShellTemplate(isUserMSI bool) {
	fmt.Print(`# ACME account email for Let's Encrypt registration
$env:LEGO_EMAIL = "your-email@example.com"
# Azure subscription and resource group
$env:AZURE_SUBSCRIPTION_ID = "your-azure-subscription-id"
$env:AZURE_RESOURCE_GROUP = "your-resource-group-name"
# Azure Key Vault for certificate storage
$env:AZURE_KEY_VAULT_URL = "https://your-keyvault.vault.azure.net/"
# Azure authentication (Managed Identity)
$env:AZURE_AUTH_METHOD = "msi"`)
	if isUserMSI {
		fmt.Print("\n$env:AZURE_CLIENT_ID = \"your-user-assigned-msi-client-id\"")
	}
}

// GenerateConfigTemplate generates configuration templates in different formats
func (g *TemplateGenerator) GenerateConfigTemplate(format string) {
	switch format {
	case "json":
		g.generateJSONConfig()
	case "toml":
		g.generateTOMLConfig()
	case "yaml", "yml":
		g.generateYAMLConfig()
	default:
		fmt.Printf("Error: Unsupported format '%s'. Supported formats: json, toml, yaml\n", format)
		fmt.Printf("For environment variables, use: azure-ssl-certificate-provisioner environment\n")
		return
	}
}

// generateJSONConfig generates JSON configuration template
func (g *TemplateGenerator) generateJSONConfig() {
	fmt.Print(`{
  "subscription": "your-azure-subscription-id",
  "resource-group": "your-resource-group-name",
  "key-vault-url": "https://your-keyvault.vault.azure.net/",
  "email": "your-email@example.com",
  "staging": true,
  "expire-threshold": 7,
  "azure-client-id": "your-service-principal-client-id",
  "azure-client-secret": "your-service-principal-client-secret",
  "azure-tenant-id": "your-azure-tenant-id",
  "zones": ["example.com", "subdomain.example.com"],
  "sp-name": "azure-ssl-cert-provisioner",
  "kv-name": "your-keyvault-name",
  "kv-resource-group": "your-keyvault-resource-group",
  "sp-no-roles": false,
  "sp-use-cert-auth": false,
  "shell": "bash"
}`)
}

// generateTOMLConfig generates TOML configuration template
func (g *TemplateGenerator) generateTOMLConfig() {
	fmt.Print(`# Azure SSL Certificate Provisioner Configuration
subscription = "your-azure-subscription-id"
resource-group = "your-resource-group-name"
key-vault-url = "https://your-keyvault.vault.azure.net/"
email = "your-email@example.com"
staging = true
expire-threshold = 7
azure-client-id = "your-service-principal-client-id"
azure-client-secret = "your-service-principal-client-secret"
azure-tenant-id = "your-azure-tenant-id"
zones = ["example.com", "subdomain.example.com"]
sp-name = "azure-ssl-cert-provisioner"
kv-name = "your-keyvault-name"
kv-resource-group = "your-keyvault-resource-group"
sp-no-roles = false
sp-use-cert-auth = false
shell = "bash"`)
}

// generateYAMLConfig generates YAML configuration template
func (g *TemplateGenerator) generateYAMLConfig() {
	fmt.Print(`# Azure SSL Certificate Provisioner Configuration
subscription: "your-azure-subscription-id"
resource-group: "your-resource-group-name"
key-vault-url: "https://your-keyvault.vault.azure.net/"
email: "your-email@example.com"
staging: true
expire-threshold: 7
azure-client-id: "your-service-principal-client-id"
azure-client-secret: "your-service-principal-client-secret"
azure-tenant-id: "your-azure-tenant-id"
zones:
  - "example.com"
  - "subdomain.example.com"
sp-name: "azure-ssl-cert-provisioner"
kv-name: "your-keyvault-name"
kv-resource-group: "your-keyvault-resource-group"
sp-no-roles: false
sp-use-cert-auth: false
shell: "bash"`)
}
