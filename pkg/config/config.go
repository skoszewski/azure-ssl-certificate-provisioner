package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/spf13/viper"
)

// ValidateRequiredEnvVars validates that all required environment variables are set
func ValidateRequiredEnvVars() error {
	// Check Azure Key Vault URL
	vaultURL := viper.GetString("key-vault-url")
	if vaultURL == "" {
		return fmt.Errorf("AZURE_KEY_VAULT_URL environment variable is required")
	}

	// Check Azure authentication variables required by lego DNS provider
	// These are needed for the Azure DNS provider to authenticate with Azure
	clientID := viper.GetString("azure-client-id")
	clientSecret := viper.GetString("azure-client-secret")
	tenantID := viper.GetString("azure-tenant-id")

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
		return fmt.Errorf("required Azure authentication environment variables are missing: %s", strings.Join(missingVars, ", "))
	}

	log.Printf("Azure authentication configured: client_id=%s, tenant_id=%s", clientID, tenantID)
	return nil
}

// SetupViper configures viper with environment variable bindings
func SetupViper() {
	// Set environment variable bindings
	viper.BindEnv("subscription", "AZURE_SUBSCRIPTION_ID")
	viper.BindEnv("resource-group", "AZURE_RESOURCE_GROUP")
	viper.BindEnv("key-vault-url", "AZURE_KEY_VAULT_URL")
	viper.BindEnv("email", "LEGO_EMAIL")

	// Azure authentication environment variables for lego DNS provider
	viper.BindEnv("azure-client-id", "AZURE_CLIENT_ID")
	viper.BindEnv("azure-client-secret", "AZURE_CLIENT_SECRET")
	viper.BindEnv("azure-tenant-id", "AZURE_TENANT_ID")

	// Set defaults
	viper.SetDefault("staging", true)
}
