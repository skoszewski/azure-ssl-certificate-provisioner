package cli

import (
	"context"
	"log"
	"os"

	"github.com/go-acme/lego/v4/lego"
	legoAzure "github.com/go-acme/lego/v4/providers/dns/azuredns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/internal/zones"
	"azure-ssl-certificate-provisioner/pkg/acme"
	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/certificate"
	"azure-ssl-certificate-provisioner/pkg/config"
	"azure-ssl-certificate-provisioner/pkg/constants"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the SSL certificate provisioner",
	Long:  `Scan Azure DNS zones and provision SSL certificates for records marked with ACME metadata.`,
	Run:   runCmdRun,
}

func runCmdSetup(cmd *cobra.Command) {
	// Configure flags for run command
	cmd.Flags().StringSliceP(constants.Zones, "z", nil, "DNS zone(s) to search for records (can be used multiple times). If omitted, all zones in the resource group will be scanned")
	cmd.Flags().StringP(constants.SubscriptionID, "s", "", "Azure subscription ID")
	cmd.Flags().StringP(constants.ResourceGroupName, "g", "", "Azure resource group name")
	cmd.Flags().Bool(constants.Staging, true, "Use Let's Encrypt staging environment")
	cmd.Flags().IntP(constants.ExpireThreshold, "t", 7, "Certificate expiration threshold in days")
	cmd.Flags().StringP(constants.Email, "e", "", "Email address for ACME account registration (required)")

	viper.BindPFlag(constants.Zones, runCmd.Flags().Lookup(constants.Zones))
	viper.BindPFlag(constants.SubscriptionID, runCmd.Flags().Lookup(constants.SubscriptionID))
	viper.BindPFlag(constants.ResourceGroupName, runCmd.Flags().Lookup(constants.ResourceGroupName))
	viper.BindPFlag(constants.Staging, runCmd.Flags().Lookup(constants.Staging))
	viper.BindPFlag(constants.ExpireThreshold, runCmd.Flags().Lookup(constants.ExpireThreshold))
	viper.BindPFlag(constants.Email, runCmd.Flags().Lookup(constants.Email))
}

// runCmdRun executes the main certificate provisioning logic
func runCmdRun(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	// Get configuration values
	subscriptionId := viper.GetString(constants.SubscriptionID)
	resourceGroupName := viper.GetString(constants.ResourceGroupName)
	staging := viper.GetBool(constants.Staging)
	email := viper.GetString(constants.Email)

	if subscriptionId == "" {
		log.Fatalf("Subscription ID not specified.")
	}

	if resourceGroupName == "" {
		log.Fatalf("Resource Group Name not specified.")
	}

	if email == "" {
		log.Fatalf("Email address not specified.")
	}

	// Validate all required environment variables
	// Validate required environment variables
	if err := config.ValidateRequiredEnvVars(); err != nil {
		log.Fatalf("Environment validation failed: %v", err)
	}

	vaultURL := viper.GetString(constants.KeyVaultURL)

	// Create Azure clients
	azureClients, err := azure.NewClients(subscriptionId, vaultURL)
	if err != nil {
		log.Fatalf("Failed to create Azure clients: %v", err)
	}

	// Configure ACME server based on staging flag
	var serverURL string
	if staging {
		serverURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		utilities.LogDefault("ACME environment: staging")
	} else {
		serverURL = "https://acme-v02.api.letsencrypt.org/directory"
		utilities.LogDefault("ACME environment: production")
	}

	// Load or create ACME account with persistence
	user, err := acme.LoadOrCreateAccount(email, serverURL)
	if err != nil {
		log.Fatalf("failed to load or create ACME account: %v", err)
	}

	config := lego.NewConfig(user)
	if config == nil {
		log.Fatalf("failed to create ACME config")
	}

	config.CADirURL = serverURL

	acmeClient, err := lego.NewClient(config)
	if err != nil {
		log.Fatalf("failed to create ACME client: %v", err)
	}

	// Set environment variables for the Azure DNS provider
	// The azuredns provider reads directly from environment variables
	if err := setAzureDNSEnvironment(subscriptionId, resourceGroupName); err != nil {
		log.Fatalf("failed to configure Azure DNS environment: %v", err)
	}

	// Create Azure DNS provider - it will automatically detect the authentication method
	provider, err := legoAzure.NewDNSProvider()
	if err != nil {
		log.Fatalf("failed to initialise Azure DNS provider: %v", err)
	}

	if err := acmeClient.Challenge.SetDNS01Provider(provider); err != nil {
		log.Fatalf("failed to set DNS challenge provider: %v", err)
	}

	// Only register if we don't have existing registration
	if user.Registration == nil {
		if err := acme.RegisterAccount(user, acmeClient); err != nil {
			log.Fatalf("Failed to register ACME account: %v", err)
		}

		// Save the account data for future runs
		if err := acme.SaveAccountData(user, serverURL); err != nil {
			utilities.LogDefault("ACME account save failed: %v", err)
		} else {
			utilities.LogDefault("ACME account saved successfully")
		}
	} else {
		utilities.LogDefault("ACME account loaded: %s", user.Email)
	}

	// Create certificate handler
	certHandler := certificate.NewHandler(acmeClient, azureClients.KVCert)

	// Create zones enumerator and process zones
	enumerator := zones.NewEnumerator(azureClients)
	if err := enumerator.EnumerateAndProcess(ctx, certHandler.ProcessFQDN); err != nil {
		log.Fatalf("Failed to enumerate and process zones: %v", err)
	}
}

// setAzureDNSEnvironment configures environment variables required by the azuredns provider
func setAzureDNSEnvironment(subscriptionID, resourceGroup string) error {
	// Set required environment variables for the azuredns provider
	if subscriptionID != "" {
		os.Setenv("AZURE_SUBSCRIPTION_ID", subscriptionID)
	}
	if resourceGroup != "" {
		os.Setenv("AZURE_RESOURCE_GROUP", resourceGroup)
	}

	// Set auth method if specified via viper
	authMethod := viper.GetString(constants.AzureAuthMethod)
	if authMethod != "" {
		os.Setenv("AZURE_AUTH_METHOD", authMethod)
		utilities.LogDefault("Azure DNS authentication method: %s", authMethod)
	}

	// Set MSI timeout if specified
	msiTimeout := viper.GetString(constants.AzureAuthMsiTimeout)
	if msiTimeout != "" {
		os.Setenv("AZURE_AUTH_MSI_TIMEOUT", msiTimeout)
	}

	return nil
}
