package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"crypto"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	legoAzure "github.com/go-acme/lego/v4/providers/dns/azure"
	"github.com/go-acme/lego/v4/registration"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
)

type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}

func (u *AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func handleFQDN(ctx context.Context, fqdn string, acmeClient *lego.Client, kvCertClient *azcertificates.Client) {
	certName := "cert-" + strings.ReplaceAll(fqdn, ".", "-")
	log.Printf("Checking %s...", fqdn)

	resp, err := kvCertClient.GetCertificate(ctx, certName, "", nil)
	daysLeft := 0
	if err == nil && resp.Attributes != nil && resp.Attributes.Expires != nil {
		expiry := *resp.Attributes.Expires
		daysLeft = int(time.Until(expiry).Hours() / 24)
		log.Printf("Existing certificate expires on %s (%d days left)", expiry.Format(time.RFC3339), daysLeft)
	} else {
		log.Printf("Certificate does not exist in Key Vault")
	}

	if daysLeft > 7 {
		log.Printf("Skipping renewal; certificate still valid")
		return
	}

	// Generate a new private key for this certificate request
	certPrivateKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	if err != nil {
		log.Printf("ERROR: failed to generate private key for %s: %v", fqdn, err)
		return
	}

	legoReq := certificate.ObtainRequest{
		Domains:    []string{fqdn},
		Bundle:     true,
		PrivateKey: certPrivateKey,
	}

	legoCert, err := acmeClient.Certificate.Obtain(legoReq)
	if err != nil {
		log.Printf("ERROR: failed to obtain certificate for %s: %v", fqdn, err)
		return
	}

	// Parse the certificate from the bundle to get expiration info
	block, _ := pem.Decode(legoCert.Certificate)
	if block == nil {
		log.Printf("ERROR: unable to parse certificate PEM for %s", fqdn)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("ERROR: unable to parse certificate for %s: %v", fqdn, err)
		return
	}

	log.Printf("Obtained new certificate expiring on %s", cert.NotAfter.Format(time.RFC3339))

	// Use modern PKCS12 encoding with the original private key (no PEM decoding needed)
	pfxData, err := pkcs12.Modern.Encode(certPrivateKey, cert, nil, "")
	if err != nil {
		log.Printf("ERROR: PKCS#12 encoding failed for %s: %v", fqdn, err)
		return
	}

	// Azure Key Vault expects base64-encoded certificate data
	base64Cert := base64.StdEncoding.EncodeToString(pfxData)
	_, err = kvCertClient.ImportCertificate(ctx, certName, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &base64Cert,
	}, nil)
	if err != nil {
		log.Printf("ERROR: failed to import certificate for %s into Key Vault: %v", fqdn, err)
		return
	}

	log.Printf("Imported certificate %s into Key Vault", certName)
}

func validateRequiredEnvVars() error {
	// Check Azure Key Vault URL
	vaultURL := viper.GetString("key-vault-url")
	if vaultURL == "" {
		return fmt.Errorf("AZURE_KEY_VAULT_URL environment variable is required")
	}

	// Check Azure authentication variables required by lego DNS provider
	// These are needed for the Azure DNS provider to authenticate with Azure
	clientID := viper.GetString("azure-client-id")
	clientSecret := viper.GetString("azure-client-secret")
	tenantID := viper.GetString("azure-tenant-id")

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
		return fmt.Errorf("required Azure authentication environment variables are missing: %s", strings.Join(missingVars, ", "))
	}

	log.Printf("Azure authentication configured - Client ID: %s, Tenant ID: %s", clientID, tenantID)
	return nil
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "azure-ssl-certificate-provisioner",
		Short: "Automatically provision SSL certificates from Let's Encrypt for Azure DNS zones",
		Long: `Azure SSL Certificate Provisioner scans Azure DNS zones for records marked with 
ACME metadata and automatically provisions SSL certificates using Let's Encrypt, 
storing them in Azure Key Vault.`,
		Run: func(cmd *cobra.Command, args []string) {
			runCertificateProvisioner()
		},
	}

	// Configure flags
	rootCmd.PersistentFlags().StringSliceP("domains", "d", nil, "Domain(s) to search for records (can be used multiple times)")
	rootCmd.PersistentFlags().StringP("subscription", "s", "", "Azure subscription ID")
	rootCmd.PersistentFlags().StringP("resource-group", "g", "", "Azure resource group name")
	rootCmd.PersistentFlags().Bool("staging", true, "Use Let's Encrypt staging environment")

	// Bind flags to viper
	viper.BindPFlag("domains", rootCmd.PersistentFlags().Lookup("domains"))
	viper.BindPFlag("subscription", rootCmd.PersistentFlags().Lookup("subscription"))
	viper.BindPFlag("resource-group", rootCmd.PersistentFlags().Lookup("resource-group"))
	viper.BindPFlag("staging", rootCmd.PersistentFlags().Lookup("staging"))

	// Set environment variable bindings
	viper.BindEnv("subscription", "AZURE_SUBSCRIPTION_ID")
	viper.BindEnv("resource-group", "RESOURCE_GROUP_NAME")
	viper.BindEnv("key-vault-url", "AZURE_KEY_VAULT_URL")

	// Azure authentication environment variables for lego DNS provider
	viper.BindEnv("azure-client-id", "AZURE_CLIENT_ID")
	viper.BindEnv("azure-client-secret", "AZURE_CLIENT_SECRET")
	viper.BindEnv("azure-tenant-id", "AZURE_TENANT_ID")

	// Set defaults
	viper.SetDefault("staging", true)

	// Mark required flags
	rootCmd.MarkPersistentFlagRequired("domains")
	rootCmd.MarkPersistentFlagRequired("subscription")
	rootCmd.MarkPersistentFlagRequired("resource-group")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Command execution failed: %v", err)
	}
}

func runCertificateProvisioner() {
	ctx := context.Background()

	// Get configuration values
	domains := viper.GetStringSlice("domains")
	subscriptionId := viper.GetString("subscription")
	resourceGroupName := viper.GetString("resource-group")
	staging := viper.GetBool("staging")

	if len(domains) == 0 {
		log.Fatalf("No domains were specified. Use -d flag at least once.")
	}

	if subscriptionId == "" {
		log.Fatalf("Subscription ID not specified.")
	}

	if resourceGroupName == "" {
		log.Fatalf("Resource Group Name not specified.")
	}

	// Validate all required environment variables
	if err := validateRequiredEnvVars(); err != nil {
		log.Fatalf("Environment validation failed: %v", err)
	}

	// Authenticate
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain Azure credential: %v", err)
	}

	dnsClient, err := armdns.NewRecordSetsClient(subscriptionId, cred, nil)
	if err != nil {
		log.Fatalf("failed to create DNS client: %v", err)
	}

	vaultURL := viper.GetString("key-vault-url")

	kvCertClient, err := azcertificates.NewClient(vaultURL, cred, nil)
	if err != nil {
		log.Fatalf("failed to create Key Vault client: %v", err)
	}

	privateKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}

	user := &AcmeUser{Email: "slawek@koszewscy.waw.pl", key: privateKey}
	config := lego.NewConfig(user)
	if config == nil {
		log.Fatalf("failed to create ACME config")
	}

	// Configure ACME server based on staging flag
	if staging {
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		log.Printf("Using Let's Encrypt staging environment")
	} else {
		config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
		log.Printf("Using Let's Encrypt production environment")
	}

	acmeClient, err := lego.NewClient(config)
	if err != nil {
		log.Fatalf("failed to create ACME client: %v", err)
	}

	provider, err := legoAzure.NewDNSProvider()
	if err != nil {
		log.Fatalf("failed to initialise Azure DNS provider: %v", err)
	}

	if err := acmeClient.Challenge.SetDNS01Provider(provider); err != nil {
		log.Fatalf("failed to set DNS challenge provider: %v", err)
	}

	reg, err := acmeClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatalf("failed to register ACME account: %v", err)
	}
	user.Registration = reg

	for _, zone := range domains {
		log.Printf("Processing DNS zone: %s", zone)
		pager := dnsClient.NewListAllByDNSZonePager(resourceGroupName, zone, nil)

		for pager.More() {
			page, err := pager.NextPage(ctx)

			if err != nil {
				log.Fatalf("failed to list record sets for zone %s: %v", zone, err)
			}

			for _, rs := range page.Value {
				if rs == nil {
					continue
				}

				fqdn := *rs.Name + "." + zone
				rsType := strings.TrimPrefix(*rs.Type, "Microsoft.Network/dnszones/")

				if rs.Properties.Metadata == nil {
					continue
				}

				val, ok := rs.Properties.Metadata["acme"]

				if val == nil {
					continue
				}

				if !ok || strings.ToLower(*val) != "true" {
					continue
				}

				if rs.Name == nil {
					continue
				}

				if rsType != "A" && rsType != "CNAME" {
					continue
				}
				log.Printf("Found record %s (%s).", fqdn, rsType)
				handleFQDN(ctx, fqdn, acmeClient, kvCertClient)
			}
		}
	}
}
