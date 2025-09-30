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

	// Check authentication method
	authMethod := viper.GetString("azure-auth-method")

	if authMethod == "msi" {
		log.Printf("MSI authentication configured")
		clientID := viper.GetString("azure-client-id")
		if clientID != "" {
			log.Printf("User-assigned MSI client ID: %s", clientID)
		} else {
			log.Printf("System-assigned MSI will be used")
		}
		return nil
	}

	// Check Azure authentication variables required by lego DNS provider
	// These are needed for the Azure DNS provider to authenticate with Azure
	clientID := viper.GetString("azure-client-id")
	clientSecret := viper.GetString("azure-client-secret")
	tenantID := viper.GetString("azure-tenant-id")

	// If no explicit auth method is set, check if we have service principal credentials
	if authMethod == "" {
		// Auto-detect based on available credentials
		if clientID != "" && clientSecret != "" && tenantID != "" {
			log.Printf("Service Principal authentication configured: client_id=%s, tenant_id=%s", clientID, tenantID)
			return nil
		}

		// Fall back to default credential chain if no explicit credentials
		log.Printf("Using Azure Default Credential chain authentication")
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

	log.Printf("Service Principal authentication configured: client_id=%s, tenant_id=%s", clientID, tenantID)
	return nil
}

// SetupViper configures viper with environment variable bindings and configuration file loading
func SetupViper() {
	// Configure configuration file loading (multi-format support)
	viper.SetConfigName("config") // Look for config.* files
	viper.AddConfigPath(".")      // Look in current directory

	// Enable automatic environment variable support
	viper.AutomaticEnv()

	// Try to read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found - this is okay, we'll use env vars and flags
			log.Printf("No configuration file found, using environment variables and command-line flags")
		} else {
			// Config file was found but another error was produced
			log.Printf("Error reading configuration file: %v", err)
		}
	} else {
		log.Printf("Using configuration file: %s", viper.ConfigFileUsed())
	}

	// Set environment variable bindings
	viper.BindEnv("subscription", "AZURE_SUBSCRIPTION_ID")
	viper.BindEnv("resource-group", "AZURE_RESOURCE_GROUP")
	viper.BindEnv("key-vault-url", "AZURE_KEY_VAULT_URL")
	viper.BindEnv("email", "LEGO_EMAIL")

	// Azure authentication environment variables for lego DNS provider
	viper.BindEnv("azure-client-id", "AZURE_CLIENT_ID")
	viper.BindEnv("azure-client-secret", "AZURE_CLIENT_SECRET")
	viper.BindEnv("azure-tenant-id", "AZURE_TENANT_ID")
	viper.BindEnv("azure-auth-method", "AZURE_AUTH_METHOD")
	viper.BindEnv("azure-auth-msi-timeout", "AZURE_AUTH_MSI_TIMEOUT")

	// Set defaults
	viper.SetDefault("staging", true)
	viper.SetDefault("azure-auth-method", "")
	viper.SetDefault("azure-auth-msi-timeout", "2s")
}
