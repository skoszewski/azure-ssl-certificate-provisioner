package cli

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/zones"
	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/config"
)

// listCertificatesAndRecords lists DNS records and their certificate status
func (c *Commands) listCertificatesAndRecords() {
	ctx := context.Background()

	// Setup configuration loading
	config.SetupViper()

	// Get configuration values (using same keys as run command)
	zonesList := viper.GetStringSlice("zones")
	subscriptionId := viper.GetString("subscription")
	resourceGroupName := viper.GetString("resource-group")
	expireThreshold := viper.GetInt("expire-threshold")
	email := viper.GetString("email")

	// Validate required parameters
	if subscriptionId == "" {
		log.Fatalf("Subscription ID not specified.")
	}

	if resourceGroupName == "" {
		log.Fatalf("Resource Group Name not specified.")
	}

	if email == "" {
		log.Fatalf("Email address not specified.")
	}

	// Validate required environment variables (but don't require ACME auth for listing)
	vaultURL := viper.GetString("key-vault-url")
	if vaultURL == "" {
		log.Fatalf("AZURE_KEY_VAULT_URL environment variable is required")
	}

	// Create Azure clients (no need for lego/ACME setup for listing)
	azureClients, err := azure.NewClients(subscriptionId, vaultURL)
	if err != nil {
		log.Fatalf("Failed to create Azure clients: %v", err)
	}

	log.Printf("List mode started: subscription=%s, resource_group=%s, key_vault=%s, expire_threshold=%d", subscriptionId, resourceGroupName, vaultURL, expireThreshold)

	// Create zones enumerator and process zones with listing processor
	enumerator := zones.NewEnumerator(azureClients)

	listProcessor := &CertificateListProcessor{
		kvClient:        azureClients.KVCert,
		expireThreshold: expireThreshold,
	}

	if err := enumerator.EnumerateAndProcess(ctx, zonesList, resourceGroupName, expireThreshold, listProcessor.ProcessFQDN); err != nil {
		log.Fatalf("Failed to enumerate and process zones: %v", err)
	}

	// Print summary
	listProcessor.PrintSummary()
}

// CertificateListProcessor processes FQDNs for listing purposes
type CertificateListProcessor struct {
	kvClient        *azcertificates.Client
	expireThreshold int
	totalRecords    int
	validCerts      int
	expiredCerts    int
	missingCerts    int
}

// ProcessFQDN processes a single FQDN for listing (matches zones.ProcessorFunc signature)
func (p *CertificateListProcessor) ProcessFQDN(ctx context.Context, fqdn string, expireThreshold int) {
	p.totalRecords++

	certName := "cert-" + strings.ReplaceAll(fqdn, ".", "-")
	log.Printf("DNS record found and marked for ACME processing")
	log.Printf("Checking certificate: %s", certName)

	// Check certificate status in Key Vault
	resp, err := p.kvClient.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		log.Printf("Certificate not found in Key Vault")
		p.missingCerts++
		return
	}

	// Check certificate expiration
	daysLeft := 0
	if resp.Attributes != nil && resp.Attributes.Expires != nil {
		daysLeft = int(time.Until(*resp.Attributes.Expires).Hours() / 24)

		if daysLeft <= expireThreshold {
			log.Printf("Certificate expires in %d days (threshold: %d)", daysLeft, expireThreshold)
			p.expiredCerts++
		} else {
			log.Printf("Certificate valid for %d days", daysLeft)
			p.validCerts++
		}
	} else {
		log.Printf("Certificate found but expiration date unavailable")
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
	log.Printf("Summary: total_records=%d, valid_certs=%d, expired_certs=%d, missing_certs=%d%s",
		p.totalRecords, p.validCerts, p.expiredCerts, p.missingCerts, needsAction)
}
