package azure

import (
	"azure-ssl-certificate-provisioner/pkg/constants"
	"context"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	legoAzure "github.com/go-acme/lego/v4/providers/dns/azuredns"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/spf13/viper"
)

var (
	authClient          *armauthorization.RoleAssignmentsClient
	dnsClient           *armdns.RecordSetsClient
	dnsZonesClient      *armdns.ZonesClient
	keyVaultCertsClient *azcertificates.Client
	graphClient         *msgraph.GraphServiceClient
	credential          *azidentity.DefaultAzureCredential
	err                 error
)

// As of time of writing (2025-10-03) the lego azuredns provided does not support
// authentication using a client certificate, only client secret or managed identity.
var authEnvMap = map[string]string{
	constants.AzureTenantID:     legoAzure.EnvTenantID,
	constants.AzureClientID:     legoAzure.EnvClientID,
	constants.AzureClientSecret: legoAzure.EnvClientSecret,
}

func GetCredential() *azidentity.DefaultAzureCredential {
	if credential == nil {
		// Set environment variables from viper if they are not already set
		// This allows using config file or flags to set auth parameters
		// but still allows env vars to override them if set
		// The azidentity.DefaultAzureCredential will use these env vars
		// if they are set, so we need to ensure they are set before creating the credential
		// but we don't want to override existing env vars
		// This is useful for CI/CD scenarios where secrets are injected as env vars
		// and should take precedence over config file or flags
		// Note: This approach assumes that if one of the auth params is set via env var,
		// the others are also set via env vars. Mixing methods is not supported.
		for viperKey, envVar := range authEnvMap {
			if os.Getenv(envVar) == "" && viper.GetString(viperKey) != "" {
				if err := os.Setenv(envVar, viper.GetString(viperKey)); err != nil {
					log.Fatalf("failed to set environment variable %s: %v", envVar, err)
				}
			}
		}

		credential, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			log.Fatalf("failed to obtain a credential: %v", err)
		}

		// Get a token to verify the credential works
		_, err = credential.GetToken(
			context.Background(),
			policy.TokenRequestOptions{
				Scopes: []string{"https://management.azure.com/.default"},
			},
		)

		if err != nil {
			log.Fatalf("Authentication failed, check your Azure credentials and permissions: %v", err)
		}
	}

	return credential
}

func GetGraphClient() *msgraph.GraphServiceClient {
	if graphClient == nil {

		graphClient, err = msgraph.NewGraphServiceClientWithCredentials(GetCredential(), nil)
		if err != nil {
			log.Fatalf("failed to create Microsoft Graph client: %v", err)
		}
	}

	return graphClient
}

func GetDnsClient() *armdns.RecordSetsClient {
	if dnsClient == nil {
		subscriptionID := viper.GetString(constants.SubscriptionID)

		if subscriptionID == "" {
			log.Fatalf("Subscription ID is required to initialize DNS client.")
		}

		if dnsClient, err = armdns.NewRecordSetsClient(subscriptionID, GetCredential(), nil); err != nil {
			log.Fatalf("failed to create DNS RecordSets client: %v", err)
		}
	}

	return dnsClient
}

func GetDnsZonesClient() *armdns.ZonesClient {
	if dnsZonesClient == nil {
		subscriptionID := viper.GetString(constants.SubscriptionID)

		if subscriptionID == "" {
			log.Fatalf("Subscription ID is required to initialize DNS Zones client.")
		}

		if dnsZonesClient, err = armdns.NewZonesClient(subscriptionID, GetCredential(), nil); err != nil {
			log.Fatalf("failed to create DNS Zones client: %v", err)
		}
	}

	return dnsZonesClient
}

func GetKeyVaultCertsClient() *azcertificates.Client {
	if keyVaultCertsClient == nil {
		vaultName := viper.GetString(constants.KeyVaultName)
		vaultURL := viper.GetString(constants.KeyVaultURL)

		if vaultName == "" && vaultURL == "" {
			log.Fatalf("Key Vault name or URL is required to initialize Key Vault Certificates client.")
		}

		if vaultURL == "" {
			vaultURL = "https://" + vaultName + ".vault.azure.net/"
		}

		if keyVaultCertsClient, err = azcertificates.NewClient(vaultURL, GetCredential(), nil); err != nil {
			log.Fatalf("failed to create Key Vault Certificates client: %v", err)
		}
	}

	return keyVaultCertsClient
}

func GetAuthClient() *armauthorization.RoleAssignmentsClient {
	if authClient == nil {
		subscriptionID := viper.GetString(constants.SubscriptionID)

		if subscriptionID == "" {
			log.Fatalf("Subscription ID is required to initialize Authorization client.")
		}

		// Create the client options with the desired API version
		clientOptions := &arm.ClientOptions{
			ClientOptions: policy.ClientOptions{
				APIVersion: "2022-04-01",
			},
		}

		authClient, err = armauthorization.NewRoleAssignmentsClient(subscriptionID, GetCredential(), clientOptions)
		if err != nil {
			log.Fatalf("failed to create authorization client: %v", err)
		}
	}

	return authClient
}
