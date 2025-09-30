package cli

import (
	"context"
	"log"
	"os"

	"github.com/go-acme/lego/v4/lego"
	legoAzure "github.com/go-acme/lego/v4/providers/dns/azuredns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/zones"
	"azure-ssl-certificate-provisioner/pkg/acme"
	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/certificate"
	"azure-ssl-certificate-provisioner/pkg/config"
)

// createRunCommand creates the run command
func (c *Commands) createRunCommand() *cobra.Command {
	var runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the SSL certificate provisioner",
		Long:  `Scan Azure DNS zones and provision SSL certificates for records marked with ACME metadata.`,
		Run: func(cmd *cobra.Command, args []string) {
			c.runCertificateProvisioner()
		},
	}

	// Configure flags for run command
	runCmd.Flags().StringSliceP("zones", "z", nil, "DNS zone(s) to search for records (can be used multiple times). If omitted, all zones in the resource group will be scanned")
	runCmd.Flags().StringP("subscription", "s", "", "Azure subscription ID")
	runCmd.Flags().StringP("resource-group", "g", "", "Azure resource group name")
	runCmd.Flags().Bool("staging", true, "Use Let's Encrypt staging environment")
	runCmd.Flags().IntP("expire-threshold", "t", 7, "Certificate expiration threshold in days")
	runCmd.Flags().StringP("email", "e", "", "Email address for ACME account registration (required)")

	// Mark required flags
	// Note: All these parameters can be provided via environment variables, so we don't use MarkFlagRequired
	// which would prevent environment variable resolution. Manual validation is done in runCertificateProvisioner()
	// Environment variables: AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, LEGO_EMAIL

	return runCmd
}

// createListCommand creates the list command
func (c *Commands) createListCommand() *cobra.Command {
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List DNS records and certificate status",
		Long:  `Scan Azure DNS zones and list records that would be processed, along with their certificate status from Key Vault.`,
		Run: func(cmd *cobra.Command, args []string) {
			c.listCertificatesAndRecords()
		},
	}

	// Configure flags for list command (same as run command)
	listCmd.Flags().StringSliceP("zones", "z", nil, "DNS zone(s) to search for records (can be used multiple times). If omitted, all zones in the resource group will be scanned")
	listCmd.Flags().StringP("subscription", "s", "", "Azure subscription ID")
	listCmd.Flags().StringP("resource-group", "g", "", "Azure resource group name")
	listCmd.Flags().Bool("staging", true, "Use Let's Encrypt staging environment")
	listCmd.Flags().IntP("expire-threshold", "t", 7, "Certificate expiration threshold in days")
	listCmd.Flags().StringP("email", "e", "", "Email address for ACME account registration (used for certificate lookup)")

	return listCmd
}

// runCertificateProvisioner executes the main certificate provisioning logic
func (c *Commands) runCertificateProvisioner() {
	ctx := context.Background()

	// Setup configuration loading
	config.SetupViper()

	// Get configuration values
	zonesList := viper.GetStringSlice("zones")
	subscriptionId := viper.GetString("subscription")
	resourceGroupName := viper.GetString("resource-group")
	staging := viper.GetBool("staging")
	expireThreshold := viper.GetInt("expire-threshold")
	email := viper.GetString("email")

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

	vaultURL := viper.GetString("key-vault-url")

	// Create Azure clients
	azureClients, err := azure.NewClients(subscriptionId, vaultURL)
	if err != nil {
		log.Fatalf("Failed to create Azure clients: %v", err)
	}

	// Configure ACME server based on staging flag
	var serverURL string
	if staging {
		serverURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		log.Printf("ACME environment: staging")
	} else {
		serverURL = "https://acme-v02.api.letsencrypt.org/directory"
		log.Printf("ACME environment: production")
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
			log.Printf("ACME account save failed: %v", err)
		} else {
			log.Printf("ACME account saved successfully")
		}
	} else {
		log.Printf("ACME account loaded: %s", user.Email)
	}

	// Create certificate handler
	certHandler := certificate.NewHandler(acmeClient, azureClients.KVCert)

	// Create zones enumerator and process zones
	enumerator := zones.NewEnumerator(azureClients)
	if err := enumerator.EnumerateAndProcess(ctx, zonesList, resourceGroupName, expireThreshold, certHandler.ProcessFQDN); err != nil {
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
	authMethod := viper.GetString("azure-auth-method")
	if authMethod != "" {
		os.Setenv("AZURE_AUTH_METHOD", authMethod)
		log.Printf("Azure DNS authentication method: %s", authMethod)
	}

	// Set MSI timeout if specified
	msiTimeout := viper.GetString("azure-auth-msi-timeout")
	if msiTimeout != "" {
		os.Setenv("AZURE_AUTH_MSI_TIMEOUT", msiTimeout)
	}

	return nil
}
