package config

import (
	"strings"

	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/pkg/constants"
	utilities "azure-ssl-certificate-provisioner/pkg/utils"

	legoAzure "github.com/go-acme/lego/v4/providers/dns/azuredns"
)

// Config represents the application configuration structure
type Config struct {
	SubscriptionID    string   `mapstructure:"subscription-id"`
	ResourceGroup     string   `mapstructure:"resource-group"`
	KeyVaultURL       string   `mapstructure:"key-vault-url"`
	Email             string   `mapstructure:"email"`
	Staging           bool     `mapstructure:"staging"`
	ExpireThreshold   int      `mapstructure:"expire-threshold"`
	AzureClientID     string   `mapstructure:"azure-client-id"`
	AzureClientSecret string   `mapstructure:"azure-client-secret"`
	AzureTenantID     string   `mapstructure:"azure-tenant-id"`
	Zones             []string `mapstructure:"zones"`
}

var configFile string

func InitConfig() {
	viper.AddConfigPath(".")
	viper.SetConfigName("config")

	if configFile != "" {
		viper.SetConfigFile(configFile)
		utilities.LogVerbose("Config file set to: %s", configFile)
	}

	if err := viper.ReadInConfig(); err == nil {
		utilities.LogVerbose("Using config file: %s", viper.ConfigFileUsed())
	} else {
		utilities.LogVerbose("No config file found, relying on environment variables and flags")
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		utilities.LogDefault("Failed to parse configuration: %v", err)
	} else {
		// Display loaded configuration for debugging
		utilities.LogVerbose("Configuration loaded successfully.")
		utilities.LogVerbose("Subscription ID: %s", cfg.SubscriptionID)
		utilities.LogVerbose("Resource Group: %s", cfg.ResourceGroup)
		utilities.LogVerbose("Key Vault URL: %s", cfg.KeyVaultURL)
		utilities.LogVerbose("Email: %s", cfg.Email)
		stagingStr := "Production"
		if cfg.Staging {
			stagingStr = "Staging"
		}
		utilities.LogVerbose("ACME environment: %s", stagingStr)
		utilities.LogVerbose("Expire Threshold: %d days", cfg.ExpireThreshold)
		utilities.LogVerbose("Azure Tenant ID: %s", cfg.AzureTenantID)
		utilities.LogVerbose("Azure Client ID: %s", cfg.AzureClientID)
		if cfg.AzureClientSecret != "" {
			utilities.LogVerbose("Azure Client Secret: [REDACTED]")
		} else {
			utilities.LogVerbose("Azure Client Secret: not set")
		}
		if len(cfg.Zones) > 0 {
			utilities.LogVerbose("DNS Zones: %s", strings.Join(cfg.Zones, ", "))
		} else {
			utilities.LogVerbose("DNS Zones: none specified")
		}
	}
}

func BindEnvVariables() {
	// Bind Viper keys to environment variables
	viper.BindEnv(constants.SubscriptionID, legoAzure.EnvSubscriptionID)
	viper.BindEnv(constants.ResourceGroupName, constants.EnvResourceGroup)
	viper.BindEnv(constants.KeyVaultURL, constants.EnvKeyVaultURL)
	viper.BindEnv(constants.Email, constants.EnvLegoEmail)

	// Azure authentication environment variables for lego DNS provider
	viper.BindEnv(constants.AzureClientID, legoAzure.EnvClientID)
	viper.BindEnv(constants.AzureClientSecret, legoAzure.EnvClientSecret)
	viper.BindEnv(constants.AzureTenantID, legoAzure.EnvTenantID)
	viper.BindEnv(constants.AzureAuthMethod, legoAzure.EnvAuthMethod)
	viper.BindEnv(constants.AzureAuthMsiTimeout, legoAzure.EnvAuthMSITimeout)
}

func SetDefaults() {
	// Set defaults
	viper.SetDefault(constants.Staging, true)
	viper.SetDefault(constants.AzureAuthMethod, "")
	viper.SetDefault(constants.AzureAuthMsiTimeout, "2s")
	viper.SetDefault(constants.ExpireThreshold, 7)
}
