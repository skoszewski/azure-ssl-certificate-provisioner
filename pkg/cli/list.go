package cli

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/providers/dns/azuredns"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"

	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/utils"
	"azure-ssl-certificate-provisioner/pkg/zones"
)

// listCmdRun lists DNS records and their certificate status
func List() {
	ctx := context.Background()

	// Get configuration values (using same keys as run command)
	subscriptionId := env.GetOrFile(azuredns.EnvSubscriptionID)
	resourceGroupName := env.GetOrFile(azuredns.EnvResourceGroup)
	vaultURL := env.GetOrFile("AZURE_KEY_VAULT_URL")

	utils.LogDefault("List mode started: subscription=%s, resource_group=%s, key_vault=%s", subscriptionId, resourceGroupName, vaultURL)

	listProcessor := &CertificateListProcessor{
		kvClient: azure.GetKeyVaultCertsClient(),
	}

	if err := zones.EnumerateAndProcess(ctx, listProcessor.ProcessFQDN); err != nil {
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
	utils.LogDefault("DNS record found and marked for ACME processing")
	utils.LogDefault("Checking certificate: %s", certName)

	// Check certificate status in Key Vault
	resp, err := p.kvClient.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		utils.LogDefault("Certificate not found in Key Vault")
		p.missingCerts++
		return
	}

	// Check certificate expiration
	daysLeft := 0
	if resp.Attributes != nil && resp.Attributes.Expires != nil {
		daysLeft = int(time.Until(*resp.Attributes.Expires).Hours() / 24)

		if daysLeft > 0 {
			utils.LogDefault("Certificate valid for %d days", daysLeft)
			p.validCerts++
		} else {
			utils.LogDefault("Certificate expired")
			p.expiredCerts++
		}
	} else {
		utils.LogDefault("Certificate found but expiration date unavailable")
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
	utils.LogDefault("Summary: total_records=%d, valid_certs=%d, expired_certs=%d, missing_certs=%d%s",
		p.totalRecords, p.validCerts, p.expiredCerts, p.missingCerts, needsAction)
}
