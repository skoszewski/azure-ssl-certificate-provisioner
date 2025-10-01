package cli

import (
	"fmt"
	"strings"

	"azure-ssl-certificate-provisioner/internal/types"
	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/constants"
)

// GenerateEnvironmentTemplate generates environment variable templates
func GenerateEnvironmentTemplate(shell string, msiType string) {
	isUserMSI := msiType == "user"

	switch strings.ToLower(shell) {
	case constants.PowerShell, "ps1":
		if msiType == "system" || msiType == "user" {
			generateMSIPowerShellTemplate(isUserMSI)
		} else {
			generatePowerShellTemplate()
		}
	case constants.Bash, "sh":
		if msiType == "system" || msiType == "user" {
			generateMSIBashTemplate(isUserMSI)
		} else {
			generateBashTemplate()
		}
	default:
		utilities.LogDefault("Unsupported shell type: shell=%s, supported=%s,%s", shell, constants.Bash, constants.PowerShell)
		if msiType == "system" || msiType == "user" {
			generateMSIBashTemplate(isUserMSI)
		} else {
			generateBashTemplate()
		}
	}
}

func generateBashTemplate() {
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
export AZURE_TENANT_ID="your-azure-tenant-id"
`)
}

func generatePowerShellTemplate() {
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
$env:AZURE_TENANT_ID = "your-azure-tenant-id"
`)
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

// MSI template methods
func generateMSIBashTemplate(isUserMSI bool) {
	fmt.Print(`# ACME account email for Let's Encrypt registration
export LEGO_EMAIL="your-email@example.com"
# Azure subscription and resource group
export AZURE_SUBSCRIPTION_ID="your-azure-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group-name"
# Azure Key Vault for certificate storage
export AZURE_KEY_VAULT_URL="https://your-keyvault.vault.azure.net/"
# Azure authentication (Managed Identity)
export AZURE_AUTH_METHOD="msi"
`)
	if isUserMSI {
		fmt.Print("export AZURE_CLIENT_ID=\"your-user-assigned-msi-client-id\"")
	}
}

func generateMSIPowerShellTemplate(isUserMSI bool) {
	fmt.Print(`# ACME account email for Let's Encrypt registration
$env:LEGO_EMAIL = "your-email@example.com"
# Azure subscription and resource group
$env:AZURE_SUBSCRIPTION_ID = "your-azure-subscription-id"
$env:AZURE_RESOURCE_GROUP = "your-resource-group-name"
# Azure Key Vault for certificate storage
$env:AZURE_KEY_VAULT_URL = "https://your-keyvault.vault.azure.net/"
# Azure authentication (Managed Identity)
$env:AZURE_AUTH_METHOD = "msi"
`)
	if isUserMSI {
		fmt.Print("$env:AZURE_CLIENT_ID = \"your-user-assigned-msi-client-id\"")
	}
}

// generateJSONConfig generates JSON configuration template
func generateJSONConfig() {
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
}
`)
}

// generateTOMLConfig generates TOML configuration template
func generateTOMLConfig() {
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
shell = "bash"
`)
}

// generateYAMLConfig generates YAML configuration template
func generateYAMLConfig() {
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
shell: "bash"
`)
}
