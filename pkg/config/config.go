package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/constants"
)

// ValidateRequiredEnvVars validates that all required environment variables are set
func ValidateRequiredEnvVars() error {
	// Check Azure Key Vault URL
	vaultURL := viper.GetString(constants.KeyVaultURL)
	if vaultURL == "" {
		return fmt.Errorf("AZURE_KEY_VAULT_URL environment variable is required")
	}

	// Check authentication method
	authMethod := viper.GetString(constants.AzureAuthMethod)

	if authMethod == "msi" {
		utilities.LogDefault("MSI authentication configured")
		clientID := viper.GetString(constants.AzureClientId)
		if clientID != "" {
			utilities.LogDefault("User-assigned MSI client ID: %s", clientID)
		} else {
			utilities.LogDefault("System-assigned MSI will be used")
		}
		return nil
	}

	// Check Azure authentication variables required by lego DNS provider
	// These are needed for the Azure DNS provider to authenticate with Azure
	clientID := viper.GetString(constants.AzureClientId)
	clientSecret := viper.GetString(constants.AzureClientSecret)
	tenantID := viper.GetString(constants.AzureTenantId)

	// If no explicit auth method is set, check if we have service principal credentials
	if authMethod == "" {
		// Auto-detect based on available credentials
		if clientID != "" && clientSecret != "" && tenantID != "" {
			utilities.LogDefault("Service Principal authentication configured: client_id=%s, tenant_id=%s", clientID, tenantID)
			return nil
		}

		// Fall back to default credential chain if no explicit credentials
		utilities.LogDefault("Using Azure Default Credential chain authentication")
		return nil
	}

	// For explicit service principal auth method
	missingVars := []string{}
	if clientID == "" {
		missingVars = append(missingVars, "AZURE_CLIENT_ID")
	}
	if clientSecret == "" {
		missingVars = append(missingVars, "AZURE_CLIENT_SECRET")
	}
	if tenantID == "" {
		missingVars = append(missingVars, "AZURE_TENANT_ID")
	}

	if len(missingVars) > 0 {
		return fmt.Errorf("required Azure authentication environment variables are missing: %s (or set AZURE_AUTH_METHOD=msi for MSI authentication)", strings.Join(missingVars, ", "))
	}

	utilities.LogDefault("Service Principal authentication configured: client_id=%s, tenant_id=%s", clientID, tenantID)
	return nil
}
