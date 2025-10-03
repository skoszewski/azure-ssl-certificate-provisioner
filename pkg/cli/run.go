package cli

import (
	"context"
	"log"
	"os"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/providers/dns/azuredns"

	"azure-ssl-certificate-provisioner/pkg/acme"
	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/certificate"
	"azure-ssl-certificate-provisioner/pkg/utils"
	"azure-ssl-certificate-provisioner/pkg/zones"
)

// runCmdRun executes the main certificate provisioning logic
func Run() {
	ctx := context.Background()

	// Get configuration values
	subscriptionId := env.GetOrFile(azuredns.EnvSubscriptionID)
	resourceGroupName := env.GetOrFile(azuredns.EnvResourceGroup)
	staging := env.GetOrFile("STAGING") == "true"
	email := env.GetOrFile("LEGO_EMAIL")

	// Configure ACME server based on staging flag
	var serverURL string
	if staging {
		serverURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		utils.LogDefault("ACME environment: staging")
	} else {
		serverURL = "https://acme-v02.api.letsencrypt.org/directory"
		utils.LogDefault("ACME environment: production")
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
	provider, err := azuredns.NewDNSProvider()
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
			utils.LogDefault("ACME account save failed: %v", err)
		} else {
			utils.LogDefault("ACME account saved successfully")
		}
	} else {
		utils.LogDefault("ACME account loaded: %s", user.Email)
	}

	// Create certificate handler
	certHandler := certificate.NewHandler(acmeClient, azure.GetKeyVaultCertsClient())

	// Create zones enumerator and process zones
	if err := zones.EnumerateAndProcess(ctx, certHandler.ProcessFQDN); err != nil {
		log.Fatalf("Failed to enumerate and process zones: %v", err)
	}
}

// setAzureDNSEnvironment configures environment variables required by the azuredns provider
func setAzureDNSEnvironment(subscriptionID, resourceGroup string) error {
	// Set required environment variables for the azuredns provider
	if subscriptionID != "" {
		os.Setenv(azuredns.EnvSubscriptionID, subscriptionID)
	}
	if resourceGroup != "" {
		os.Setenv(azuredns.EnvResourceGroup, resourceGroup)
	}

	authMethod := env.GetOrFile(azuredns.EnvAuthMethod)
	if authMethod != "" {
		os.Setenv(azuredns.EnvAuthMethod, authMethod)
		utils.LogDefault("Azure DNS authentication method: %s", authMethod)
	}

	// Set MSI timeout if specified
	msiTimeout := env.GetOrFile(azuredns.EnvAuthMSITimeout)
	if msiTimeout != "" {
		os.Setenv(azuredns.EnvAuthMSITimeout, msiTimeout)
	}

	return nil
}
