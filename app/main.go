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

func handleFQDN(ctx context.Context, fqdn string, acmeClient *lego.Client, kvCertClient *azcertificates.Client, expireThreshold int) {
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

	if daysLeft > expireThreshold {
		log.Printf("Skipping renewal; certificate still valid (expires in %d days, threshold is %d days)", daysLeft, expireThreshold)
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

func generateEnvironmentTemplate() {
	shell := viper.GetString("shell")

	switch strings.ToLower(shell) {
	case "powershell", "ps1":
		generatePowerShellTemplate()
	case "bash", "sh":
		generateBashTemplate()
	default:
		log.Printf("Unsupported shell type: %s. Supported types: bash, powershell", shell)
		generateBashTemplate()
	}
}

func generateBashTemplate() {
	fmt.Println("# Azure SSL Certificate Provisioner - Environment Variables")
	fmt.Println("# Copy and modify these values for your environment")
	fmt.Println()
	fmt.Println("# Azure subscription and resource group")
	fmt.Println("export AZURE_SUBSCRIPTION_ID=\"your-azure-subscription-id\"")
	fmt.Println("export RESOURCE_GROUP_NAME=\"your-resource-group-name\"")
	fmt.Println()
	fmt.Println("# Azure Key Vault for certificate storage")
	fmt.Println("export AZURE_KEY_VAULT_URL=\"https://your-keyvault.vault.azure.net/\"")
	fmt.Println()
	fmt.Println("# Azure authentication (Service Principal)")
	fmt.Println("export AZURE_CLIENT_ID=\"your-service-principal-client-id\"")
	fmt.Println("export AZURE_CLIENT_SECRET=\"your-service-principal-client-secret\"")
	fmt.Println("export AZURE_TENANT_ID=\"your-azure-tenant-id\"")
	fmt.Println()
	fmt.Println("# Usage example:")
	fmt.Println("# ./azure-ssl-certificate-provisioner run -d example.com -d '*.example.com'")
}

func generatePowerShellTemplate() {
	fmt.Println("# Azure SSL Certificate Provisioner - Environment Variables")
	fmt.Println("# Copy and modify these values for your environment")
	fmt.Println()
	fmt.Println("# Azure subscription and resource group")
	fmt.Println("$env:AZURE_SUBSCRIPTION_ID = \"your-azure-subscription-id\"")
	fmt.Println("$env:RESOURCE_GROUP_NAME = \"your-resource-group-name\"")
	fmt.Println()
	fmt.Println("# Azure Key Vault for certificate storage")
	fmt.Println("$env:AZURE_KEY_VAULT_URL = \"https://your-keyvault.vault.azure.net/\"")
	fmt.Println()
	fmt.Println("# Azure authentication (Service Principal)")
	fmt.Println("$env:AZURE_CLIENT_ID = \"your-service-principal-client-id\"")
	fmt.Println("$env:AZURE_CLIENT_SECRET = \"your-service-principal-client-secret\"")
	fmt.Println("$env:AZURE_TENANT_ID = \"your-azure-tenant-id\"")
	fmt.Println()
	fmt.Println("# Usage example:")
	fmt.Println("# .\\azure-ssl-certificate-provisioner.exe run -d example.com -d '*.example.com'")
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "azure-ssl-certificate-provisioner",
		Short: "Automatically provision SSL certificates from Let's Encrypt for Azure DNS zones",
		Long: `Azure SSL Certificate Provisioner scans Azure DNS zones for records marked with 
ACME metadata and automatically provisions SSL certificates using Let's Encrypt, 
storing them in Azure Key Vault.`,
	}

	// Create run subcommand
	var runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the SSL certificate provisioner",
		Long:  `Scan Azure DNS zones and provision SSL certificates for records marked with ACME metadata.`,
		Run: func(cmd *cobra.Command, args []string) {
			runCertificateProvisioner()
		},
	}

	// Configure flags for run command
	runCmd.Flags().StringSliceP("domains", "d", nil, "Domain(s) to search for records (can be used multiple times)")
	runCmd.Flags().StringP("subscription", "s", "", "Azure subscription ID")
	runCmd.Flags().StringP("resource-group", "g", "", "Azure resource group name")
	runCmd.Flags().Bool("staging", true, "Use Let's Encrypt staging environment")
	runCmd.Flags().IntP("expire-threshold", "t", 7, "Certificate expiration threshold in days")

	// Create environment subcommand
	var envCmd = &cobra.Command{
		Use:   "environment",
		Short: "Generate environment variable templates",
		Long:  `Generate Bash or PowerShell environment variable templates for required configuration.`,
		Run: func(cmd *cobra.Command, args []string) {
			generateEnvironmentTemplate()
		},
	}

	envCmd.Flags().StringP("shell", "s", "bash", "Shell type for template (bash, powershell)")

	// Bind flags to viper for run command
	viper.BindPFlag("domains", runCmd.Flags().Lookup("domains"))
	viper.BindPFlag("subscription", runCmd.Flags().Lookup("subscription"))
	viper.BindPFlag("resource-group", runCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("staging", runCmd.Flags().Lookup("staging"))
	viper.BindPFlag("expire-threshold", runCmd.Flags().Lookup("expire-threshold"))

	// Bind flags for environment command
	viper.BindPFlag("shell", envCmd.Flags().Lookup("shell"))

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

	// Mark required flags for run command
	runCmd.MarkFlagRequired("domains")
	runCmd.MarkFlagRequired("subscription")
	runCmd.MarkFlagRequired("resource-group")

	// Add subcommands to root command
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(envCmd)

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
	expireThreshold := viper.GetInt("expire-threshold")

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
				handleFQDN(ctx, fqdn, acmeClient, kvCertClient, expireThreshold)
			}
		}
	}
}
