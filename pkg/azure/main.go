package azure

import (
	"azure-ssl-certificate-provisioner/pkg/constants"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
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

func GetCredential() *azidentity.DefaultAzureCredential {
	if credential == nil {
		credential, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			log.Fatalf("failed to obtain a credential: %v", err)
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

		authClient, err = armauthorization.NewRoleAssignmentsClient(subscriptionID, credential, clientOptions)
		if err != nil {
			log.Fatalf("failed to create authorization client: %v", err)
		}
	}

	return authClient
}
