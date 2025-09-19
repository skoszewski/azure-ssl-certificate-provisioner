package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

type ServicePrincipalInfo struct {
	ApplicationID      string
	ClientID           string
	ClientSecret       string
	ServicePrincipalID string
	SubscriptionID     string
	TenantID           string
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
	fmt.Println("# ACME account email for Let's Encrypt registration")
	fmt.Println("export ACME_EMAIL=\"your-email@example.com\"")
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
	fmt.Println("# ACME account email for Let's Encrypt registration")
	fmt.Println("$env:ACME_EMAIL = \"your-email@example.com\"")
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

func createServicePrincipal(displayName, tenantID, subscriptionID string, assignDNSRole bool, resourceGroupName, keyVaultName, keyVaultResourceGroup string) (*ServicePrincipalInfo, error) {
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain Azure credential: %v", err)
	}

	// Create Microsoft Graph client
	graphClient, err := msgraph.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return nil, fmt.Errorf("failed to create Graph client: %v", err)
	}

	// Validate provided tenant and subscription IDs
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if subscriptionID == "" {
		return nil, fmt.Errorf("subscription ID is required")
	}

	// Create the Azure AD application
	application := models.NewApplication()
	application.SetDisplayName(&displayName)

	createdApp, err := graphClient.Applications().Post(context.Background(), application, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure AD application: %v", err)
	}

	applicationID := createdApp.GetId()
	clientID := createdApp.GetAppId()

	if applicationID == nil || clientID == nil {
		return nil, fmt.Errorf("failed to get application IDs")
	}

	// Create service principal for the application
	servicePrincipal := models.NewServicePrincipal()
	servicePrincipal.SetAppId(clientID)

	createdSP, err := graphClient.ServicePrincipals().Post(context.Background(), servicePrincipal, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create service principal: %v", err)
	}

	servicePrincipalID := createdSP.GetId()
	if servicePrincipalID == nil {
		return nil, fmt.Errorf("failed to get service principal ID")
	}

	// Create client secret
	passwordCredential := models.NewPasswordCredential()
	displayNameStr := "Generated by azure-ssl-certificate-provisioner"
	passwordCredential.SetDisplayName(&displayNameStr)

	addPasswordRequest := applications.NewItemAddPasswordPostRequestBody()
	addPasswordRequest.SetPasswordCredential(passwordCredential)

	secret, err := graphClient.Applications().ByApplicationId(*applicationID).AddPassword().Post(context.Background(), addPasswordRequest, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client secret: %v", err)
	}

	clientSecret := secret.GetSecretText()
	if clientSecret == nil {
		return nil, fmt.Errorf("failed to get client secret")
	}

	spInfo := &ServicePrincipalInfo{
		ApplicationID:      *applicationID,
		ClientID:           *clientID,
		ClientSecret:       *clientSecret,
		ServicePrincipalID: *servicePrincipalID,
		SubscriptionID:     subscriptionID,
		TenantID:           tenantID,
	}

	// Optionally assign DNS Zone Contributor role
	if assignDNSRole && resourceGroupName != "" {
		if err := assignDNSZoneContributorRole(spInfo, resourceGroupName, cred); err != nil {
			log.Printf("Warning: Failed to assign DNS Zone Contributor role: %v", err)
		} else {
			log.Printf("Successfully assigned DNS Zone Contributor role to resource group: %s", resourceGroupName)
		}
	}

	// Optionally assign Key Vault Certificates Officer role
	if keyVaultName != "" && keyVaultResourceGroup != "" {
		if err := assignKeyVaultCertificatesOfficerRole(spInfo, keyVaultName, keyVaultResourceGroup, cred); err != nil {
			log.Printf("Warning: Failed to assign Key Vault Certificates Officer role: %v", err)
		} else {
			log.Printf("Successfully assigned Key Vault Certificates Officer role to Key Vault: %s", keyVaultName)
		}
	}

	return spInfo, nil
}

func assignDNSZoneContributorRole(spInfo *ServicePrincipalInfo, resourceGroupName string, cred *azidentity.DefaultAzureCredential) error {
	authClient, err := armauthorization.NewRoleAssignmentsClient(spInfo.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create authorization client: %v", err)
	}

	// DNS Zone Contributor role ID
	dnsZoneContributorRoleID := "/subscriptions/" + spInfo.SubscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/befefa01-2a29-4197-83a8-272ff33ce314"

	// Resource group scope
	scope := "/subscriptions/" + spInfo.SubscriptionID + "/resourceGroups/" + resourceGroupName

	// Generate a unique role assignment ID
	roleAssignmentID := uuid.New().String()

	roleAssignmentProperties := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: &dnsZoneContributorRoleID,
			PrincipalID:      &spInfo.ServicePrincipalID,
		},
	}

	_, err = authClient.Create(context.Background(), scope, roleAssignmentID, roleAssignmentProperties, nil)
	if err != nil {
		return fmt.Errorf("failed to create role assignment: %v", err)
	}

	return nil
}

func assignKeyVaultCertificatesOfficerRole(spInfo *ServicePrincipalInfo, keyVaultName, keyVaultResourceGroup string, cred *azidentity.DefaultAzureCredential) error {
	authClient, err := armauthorization.NewRoleAssignmentsClient(spInfo.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create authorization client: %v", err)
	}

	// Key Vault Certificates Officer role ID
	keyVaultCertificatesOfficerRoleID := "/subscriptions/" + spInfo.SubscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/a4417e6f-fecd-4de8-b567-7b0420556985"

	// Key Vault scope
	scope := "/subscriptions/" + spInfo.SubscriptionID + "/resourceGroups/" + keyVaultResourceGroup + "/providers/Microsoft.KeyVault/vaults/" + keyVaultName

	// Generate a unique role assignment ID
	roleAssignmentID := uuid.New().String()

	roleAssignmentProperties := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: &keyVaultCertificatesOfficerRoleID,
			PrincipalID:      &spInfo.ServicePrincipalID,
		},
	}

	_, err = authClient.Create(context.Background(), scope, roleAssignmentID, roleAssignmentProperties, nil)
	if err != nil {
		return fmt.Errorf("failed to create role assignment: %v", err)
	}

	return nil
}

func generateServicePrincipalTemplate(spInfo *ServicePrincipalInfo, shell, keyVaultName, keyVaultResourceGroup string) {
	switch strings.ToLower(shell) {
	case "powershell", "ps1":
		generateServicePrincipalPowerShellTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	case "bash", "sh":
		generateServicePrincipalBashTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	default:
		log.Printf("Unsupported shell type: %s. Using bash format", shell)
		generateServicePrincipalBashTemplate(spInfo, keyVaultName, keyVaultResourceGroup)
	}
}

func generateServicePrincipalBashTemplate(spInfo *ServicePrincipalInfo, keyVaultName, keyVaultResourceGroup string) {
	fmt.Println("export ACME_EMAIL=\"your-email@example.com\"")
	fmt.Printf("export AZURE_SUBSCRIPTION_ID=\"%s\"\n", spInfo.SubscriptionID)
	fmt.Printf("export AZURE_TENANT_ID=\"%s\"\n", spInfo.TenantID)
	if keyVaultResourceGroup != "" {
		fmt.Printf("export RESOURCE_GROUP_NAME=\"%s\"\n", keyVaultResourceGroup)
	} else {
		fmt.Println("export RESOURCE_GROUP_NAME=\"your-resource-group-name\"")
	}
	if keyVaultName != "" {
		fmt.Printf("export AZURE_KEY_VAULT_URL=\"https://%s.vault.azure.net/\"\n", keyVaultName)
	} else {
		fmt.Println("export AZURE_KEY_VAULT_URL=\"https://your-keyvault.vault.azure.net/\"")
	}
	fmt.Printf("export AZURE_CLIENT_ID=\"%s\"\n", spInfo.ClientID)
	fmt.Printf("export AZURE_CLIENT_SECRET=\"%s\"\n", spInfo.ClientSecret)
}

func generateServicePrincipalPowerShellTemplate(spInfo *ServicePrincipalInfo, keyVaultName, keyVaultResourceGroup string) {
	fmt.Println("$env:ACME_EMAIL = \"your-email@example.com\"")
	fmt.Printf("$env:AZURE_SUBSCRIPTION_ID = \"%s\"\n", spInfo.SubscriptionID)
	fmt.Printf("$env:AZURE_TENANT_ID = \"%s\"\n", spInfo.TenantID)
	if keyVaultResourceGroup != "" {
		fmt.Printf("$env:RESOURCE_GROUP_NAME = \"%s\"\n", keyVaultResourceGroup)
	} else {
		fmt.Println("$env:RESOURCE_GROUP_NAME = \"your-resource-group-name\"")
	}
	if keyVaultName != "" {
		fmt.Printf("$env:AZURE_KEY_VAULT_URL = \"https://%s.vault.azure.net/\"\n", keyVaultName)
	} else {
		fmt.Println("$env:AZURE_KEY_VAULT_URL = \"https://your-keyvault.vault.azure.net/\"")
	}
	fmt.Printf("$env:AZURE_CLIENT_ID = \"%s\"\n", spInfo.ClientID)
	fmt.Printf("$env:AZURE_CLIENT_SECRET = \"%s\"\n", spInfo.ClientSecret)
}

func runCreateServicePrincipal() {
	displayName := viper.GetString("name")
	tenantID := viper.GetString("tenant-id")
	subscriptionID := viper.GetString("subscription-id")
	assignRole := viper.GetBool("assign-dns-role")
	resourceGroup := viper.GetString("resource-group")
	keyVaultName := viper.GetString("kv-name")
	keyVaultResourceGroup := viper.GetString("kv-resource-group")
	shell := viper.GetString("shell")

	if displayName == "" {
		log.Fatalf("Display name is required. Use --name flag.")
	}

	if tenantID == "" {
		log.Fatalf("Tenant ID is required. Use --tenant-id flag.")
	}

	if subscriptionID == "" {
		log.Fatalf("Subscription ID is required. Use --subscription-id flag.")
	}

	if assignRole && resourceGroup == "" {
		log.Fatalf("Resource group is required when assigning DNS role. Use --resource-group flag.")
	}

	// If kv-resource-group is not specified but kv-name is, use resource-group as fallback
	if keyVaultName != "" && keyVaultResourceGroup == "" {
		keyVaultResourceGroup = resourceGroup
		if keyVaultResourceGroup == "" {
			log.Fatalf("Resource group is required when assigning Key Vault role. Use --resource-group or --kv-resource-group flag.")
		}
		log.Printf("Using resource group '%s' for Key Vault '%s' role assignment", keyVaultResourceGroup, keyVaultName)
	}

	log.Printf("Creating service principal: %s", displayName)
	spInfo, err := createServicePrincipal(displayName, tenantID, subscriptionID, assignRole, resourceGroup, keyVaultName, keyVaultResourceGroup)
	if err != nil {
		log.Fatalf("Failed to create service principal: %v", err)
	}

	log.Printf("Successfully created service principal!")
	log.Printf("Application ID: %s", spInfo.ApplicationID)
	log.Printf("Client ID: %s", spInfo.ClientID)
	log.Printf("Service Principal ID: %s", spInfo.ServicePrincipalID)
	fmt.Println()

	generateServicePrincipalTemplate(spInfo, shell, keyVaultName, keyVaultResourceGroup)
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
	runCmd.Flags().StringP("email", "e", "", "Email address for ACME account registration (required)")

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

	// Create service principal subcommand
	var createSPCmd = &cobra.Command{
		Use:   "create-service-principal",
		Short: "Create Azure service principal for SSL certificate provisioning",
		Long:  `Create an Azure AD application and service principal with optional DNS Zone Contributor role assignment.`,
		Run: func(cmd *cobra.Command, args []string) {
			runCreateServicePrincipal()
		},
	}

	createSPCmd.Flags().StringP("name", "n", "", "Display name for the Azure AD application (required)")
	createSPCmd.Flags().StringP("tenant-id", "t", "", "Azure tenant ID (required)")
	createSPCmd.Flags().StringP("subscription-id", "s", "", "Azure subscription ID (required)")
	createSPCmd.Flags().Bool("assign-dns-role", false, "Assign DNS Zone Contributor role to the specified resource group")
	createSPCmd.Flags().StringP("resource-group", "g", "", "Resource group name for DNS Zone Contributor role assignment")
	createSPCmd.Flags().StringP("kv-name", "", "", "Key Vault name for Certificates Officer role assignment")
	createSPCmd.Flags().StringP("kv-resource-group", "", "", "Resource group name for the Key Vault")
	createSPCmd.Flags().StringP("shell", "", "bash", "Shell type for output template (bash, powershell)")

	// Bind flags to viper for run command
	viper.BindPFlag("domains", runCmd.Flags().Lookup("domains"))
	viper.BindPFlag("subscription", runCmd.Flags().Lookup("subscription"))
	viper.BindPFlag("resource-group", runCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("staging", runCmd.Flags().Lookup("staging"))
	viper.BindPFlag("expire-threshold", runCmd.Flags().Lookup("expire-threshold"))
	viper.BindPFlag("email", runCmd.Flags().Lookup("email"))

	// Bind flags for environment command
	viper.BindPFlag("shell", envCmd.Flags().Lookup("shell"))

	// Bind flags for create-service-principal command
	viper.BindPFlag("name", createSPCmd.Flags().Lookup("name"))
	viper.BindPFlag("tenant-id", createSPCmd.Flags().Lookup("tenant-id"))
	viper.BindPFlag("subscription-id", createSPCmd.Flags().Lookup("subscription-id"))
	viper.BindPFlag("assign-dns-role", createSPCmd.Flags().Lookup("assign-dns-role"))
	viper.BindPFlag("resource-group", createSPCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("kv-name", createSPCmd.Flags().Lookup("kv-name"))
	viper.BindPFlag("kv-resource-group", createSPCmd.Flags().Lookup("kv-resource-group"))
	viper.BindPFlag("shell", createSPCmd.Flags().Lookup("shell"))

	// Set environment variable bindings
	viper.BindEnv("subscription", "AZURE_SUBSCRIPTION_ID")
	viper.BindEnv("resource-group", "RESOURCE_GROUP_NAME")
	viper.BindEnv("key-vault-url", "AZURE_KEY_VAULT_URL")
	viper.BindEnv("email", "ACME_EMAIL")

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
	runCmd.MarkFlagRequired("email")

	// Mark required flags for create-service-principal command
	createSPCmd.MarkFlagRequired("name")
	createSPCmd.MarkFlagRequired("tenant-id")
	createSPCmd.MarkFlagRequired("subscription-id")

	// Add subcommands to root command
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(createSPCmd)

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
	email := viper.GetString("email")

	if len(domains) == 0 {
		log.Fatalf("No domains were specified. Use -d flag at least once.")
	}

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

	user := &AcmeUser{Email: email, key: privateKey}
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
