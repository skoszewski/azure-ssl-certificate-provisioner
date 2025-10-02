package cli

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/internal/zones"
	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/config"
	"azure-ssl-certificate-provisioner/pkg/constants"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List DNS records and certificate status",
	Long:    `Scan Azure DNS zones and list records that would be processed, along with their certificate status from Key Vault.`,
	Run:     listCmdRun,
	PreRunE: listCmdPreRunE,
}

func listCmdSetup(cmd *cobra.Command) {
	cmd.Flags().StringSliceP(constants.Zones, "z", nil, "DNS zone(s) to search for records (can be used multiple times). If omitted, all zones in the resource group will be scanned")
	cmd.Flags().StringP(constants.SubscriptionID, "s", "", "Azure subscription ID")
	cmd.Flags().StringP(constants.ResourceGroupName, "g", "", "Azure resource group name")
	cmd.Flags().StringP(constants.KeyVaultURL, "k", "", "Key Vault URL where certificates are stored")

	BindPFlag(cmd, constants.Zones)
	BindPFlag(cmd, constants.SubscriptionID)
	BindPFlag(cmd, constants.ResourceGroupName)
	BindPFlag(cmd, constants.KeyVaultURL)
}

func listCmdPreRunE(cmd *cobra.Command, args []string) error {
	// Initialize configuration
	config.InitConfig()

	// Validate required parameters
	if viper.GetString(constants.SubscriptionID) == "" {
		utilities.LogFatal("Subscription ID not specified")
	}

	if viper.GetString(constants.ResourceGroupName) == "" {
		utilities.LogFatal("Resource group name not specified")
	}

	if viper.GetString(constants.KeyVaultURL) == "" {
		utilities.LogFatal("Azure Key Vault URL not specified")
	}

	if viper.GetString(constants.Email) == "" {
		utilities.LogFatal("Email address not specified")
	}

	return nil
}

// listCmdRun lists DNS records and their certificate status
func listCmdRun(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	// Get configuration values (using same keys as run command)
	subscriptionId := viper.GetString(constants.SubscriptionID)
	resourceGroupName := viper.GetString(constants.ResourceGroupName)
	vaultURL := viper.GetString(constants.KeyVaultURL)

	// Create Azure clients (no need for lego/ACME setup for listing)
	azureClients, err := azure.NewClients(subscriptionId, vaultURL)
	if err != nil {
		log.Fatalf("Failed to create Azure clients: %v", err)
	}

	utilities.LogDefault("List mode started: subscription=%s, resource_group=%s, key_vault=%s", subscriptionId, resourceGroupName, vaultURL)

	// Create zones enumerator and process zones with listing processor
	enumerator := zones.NewEnumerator(azureClients)

	listProcessor := &CertificateListProcessor{
		kvClient: azureClients.KVCert,
	}

	if err := enumerator.EnumerateAndProcess(ctx, listProcessor.ProcessFQDN); err != nil {
		log.Fatalf("Failed to enumerate and process zones: %v", err)
	}

	// Print summary
	listProcessor.PrintSummary()
}

// CertificateListProcessor processes FQDNs for listing purposes
type CertificateListProcessor struct {
	kvClient     *azcertificates.Client
	totalRecords int
	validCerts   int
	expiredCerts int
	missingCerts int
}

// ProcessFQDN processes a single FQDN for listing (matches zones.ProcessorFunc signature)
func (p *CertificateListProcessor) ProcessFQDN(ctx context.Context, fqdn string) {
	p.totalRecords++

	certName := "cert-" + strings.ReplaceAll(fqdn, ".", "-")
	utilities.LogDefault("DNS record found and marked for ACME processing")
	utilities.LogDefault("Checking certificate: %s", certName)

	// Check certificate status in Key Vault
	resp, err := p.kvClient.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		utilities.LogDefault("Certificate not found in Key Vault")
		p.missingCerts++
		return
	}

	// Check certificate expiration
	daysLeft := 0
	if resp.Attributes != nil && resp.Attributes.Expires != nil {
		daysLeft = int(time.Until(*resp.Attributes.Expires).Hours() / 24)

		if daysLeft > 0 {
			utilities.LogDefault("Certificate valid for %d days", daysLeft)
			p.validCerts++
		} else {
			utilities.LogDefault("Certificate expired")
			p.expiredCerts++
		}
	} else {
		utilities.LogDefault("Certificate found but expiration date unavailable")
		p.missingCerts++
	}
}

// PrintSummary prints a summary of the listing results
func (p *CertificateListProcessor) PrintSummary() {
	needsAction := ""
	if p.expiredCerts > 0 || p.missingCerts > 0 {
		needsAction = ", action_needed=true"
	} else {
		needsAction = ", action_needed=false"
	}
	utilities.LogDefault("Summary: total_records=%d, valid_certs=%d, expired_certs=%d, missing_certs=%d%s",
		p.totalRecords, p.validCerts, p.expiredCerts, p.missingCerts, needsAction)
}
