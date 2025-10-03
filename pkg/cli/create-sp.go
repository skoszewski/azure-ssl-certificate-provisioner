package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/constants"
	"azure-ssl-certificate-provisioner/pkg/types"
	"azure-ssl-certificate-provisioner/pkg/utils"
)

const (
	DNSZoneContributorRoleID          = "befefa01-2a29-4197-83a8-272ff33ce314"
	KeyVaultCertificatesOfficerRoleID = "a4417e6f-fecd-4de8-b567-7b0420556985"
)

var createSPCmd = &cobra.Command{
	Use:     "create-sp",
	Short:   "Create Azure service principal for SSL certificate provisioning",
	Long:    `Create an Azure AD application and service principal with optional role assignments for DNS and Key Vault access.`,
	Run:     createSPCmdRun,
	PreRunE: createSPCmdPreRunE,
}

func createSPCmdSetup(cmd *cobra.Command) {
	cmd.Flags().StringP(constants.Name, "n", "", "Display name for the Azure AD application (required)")
	cmd.Flags().StringP(constants.TenantID, "t", "", "Azure tenant ID (required)")
	cmd.Flags().StringP(constants.SubscriptionID, "s", "", "Azure subscription ID (required)")
	cmd.Flags().StringP(constants.ResourceGroupName, "g", "", "Resource group name for DNS Zone Contributor role assignment")
	cmd.Flags().String(constants.KeyVaultName, "", "Key Vault name for Certificates Officer role assignment")
	cmd.Flags().String(constants.KeyVaultRG, "", "Resource group name for the Key Vault")
	cmd.Flags().Bool(constants.DryRun, false, "Output the service principal details without creating it")
	cmd.Flags().Bool(constants.UseCertAuth, false, "Use certificate-based authentication (expects {client-id}.key and {client-id}.crt files)")
	cmd.Flags().String(constants.Shell, utils.GetDefaultShell(), "Shell type for output template (bash, powershell)")

	viper.BindPFlag(constants.Name, createSPCmd.Flags().Lookup(constants.Name))
	viper.BindPFlag(constants.TenantID, createSPCmd.Flags().Lookup(constants.TenantID))
	viper.BindPFlag(constants.SubscriptionID, createSPCmd.Flags().Lookup(constants.SubscriptionID))
	viper.BindPFlag(constants.ResourceGroupName, createSPCmd.Flags().Lookup(constants.ResourceGroupName))
	viper.BindPFlag(constants.KeyVaultName, createSPCmd.Flags().Lookup(constants.KeyVaultName))
	viper.BindPFlag(constants.KeyVaultRG, createSPCmd.Flags().Lookup(constants.KeyVaultRG))
	viper.BindPFlag(constants.DryRun, createSPCmd.Flags().Lookup(constants.DryRun))
	viper.BindPFlag(constants.UseCertAuth, createSPCmd.Flags().Lookup(constants.UseCertAuth))
	viper.BindPFlag(constants.Shell, createSPCmd.Flags().Lookup(constants.Shell))
}

func createSPCmdPreRunE(cmd *cobra.Command, args []string) error {
	if viper.GetString(constants.Name) == "" {
		log.Fatalf("Display name is required. Use --%s flag.", constants.Name)
	}

	if viper.GetString(constants.TenantID) == "" {
		log.Fatalf("Tenant ID is required. Use --%s flag.", constants.TenantID)
	}

	return nil
}

// createSPCmdRun executes the service principal creation logic
func createSPCmdRun(cmd *cobra.Command, args []string) {
	displayName := viper.GetString(constants.Name)
	tenantID := viper.GetString(constants.TenantID)

	if viper.GetBool(constants.DryRun) {
		utils.LogDefault("Dry run mode: service principal not created")
		return
	}

	utils.LogDefault("Service principal creation started: %s", displayName)

	spInfo, err := CreateServicePrincipal(displayName, tenantID)
	if err != nil {
		log.Fatalf("Failed to create service principal: %v", err)
	}

	utils.LogDefault("Service principal created: application_id=%s, client_id=%s, service_principal_id=%s", spInfo.ApplicationID, spInfo.ClientID, spInfo.ServicePrincipalID)
}

// CreateServicePrincipal creates a new Azure AD application and service principal
func CreateServicePrincipal(displayName string, tenantID string) (*types.ServicePrincipalInfo, error) {
	if displayName == "" {
		return nil, fmt.Errorf("display name is required")
	}

	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}

	// Create the service principal info struct
	spInfo := &types.ServicePrincipalInfo{
		TenantID:    tenantID,
		UseCertAuth: viper.GetBool(constants.UseCertAuth),
	}

	// Create the Azure AD appDefinition model
	appDefinition := models.NewApplication()
	appDefinition.SetDisplayName(&displayName)

	// Initialize the Microsoft Graph client and create the application
	createdApp, err := azure.GetGraphClient().Applications().Post(context.Background(), appDefinition, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure AD application: %v", err)
	}

	if createdApp.GetId() == nil || createdApp.GetAppId() == nil {
		return nil, fmt.Errorf("failed to get application IDs")
	}

	spInfo.ApplicationID = *createdApp.GetId()
	spInfo.ClientID = *createdApp.GetAppId()

	// Create service principal for the application
	servicePrincipal := models.NewServicePrincipal()
	servicePrincipal.SetAppId(createdApp.GetAppId())

	createdSP, err := azure.GetGraphClient().ServicePrincipals().Post(context.Background(), servicePrincipal, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create service principal: %v", err)
	}

	if createdSP.GetId() == nil {
		return nil, fmt.Errorf("failed to get service principal ID")
	}

	spInfo.ServicePrincipalID = *createdSP.GetId()

	if spInfo.UseCertAuth {
		// Derive certificate and private key paths from client ID
		privateKeyPath := fmt.Sprintf("%s.key", spInfo.ClientID)
		certificatePath := fmt.Sprintf("%s.crt", spInfo.ClientID)
		spInfo.PrivateKeyPath = privateKeyPath
		spInfo.CertificatePath = certificatePath

		// Use certificate-based authentication
		err := setupCertificateAuth(spInfo.ApplicationID, privateKeyPath, certificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to setup certificate authentication: %v", err)
		}
		log.Printf("Certificate authentication configured for application: key=%s, cert=%s", privateKeyPath, certificatePath)
	} else {
		// Create client secret
		passwordCredential := models.NewPasswordCredential()
		displayNameStr := "Generated by azure-ssl-certificate-provisioner"
		passwordCredential.SetDisplayName(&displayNameStr)

		addPasswordRequest := applications.NewItemAddPasswordPostRequestBody()
		addPasswordRequest.SetPasswordCredential(passwordCredential)

		secret, err := azure.GetGraphClient().Applications().ByApplicationId(spInfo.ApplicationID).AddPassword().Post(context.Background(), addPasswordRequest, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create client secret: %v", err)
		}

		if secret.GetSecretText() == nil {
			return nil, fmt.Errorf("failed to get client secret")
		}

		spInfo.ClientSecret = *secret.GetSecretText()
	}

	subscriptionID := viper.GetString(constants.SubscriptionID)
	resourceGroupName := viper.GetString(constants.ResourceGroupName)

	if subscriptionID == "" || resourceGroupName == "" {
		log.Printf("Subscription ID or Resource Group name not provided; skipping DNS role assignments")
	} else {
		if err := assignDNSZoneContributorRole(spInfo, subscriptionID, resourceGroupName); err != nil {
			log.Printf("DNS Zone Contributor role assignment failed: subscription=%s, resource_group=%s, error=%v", subscriptionID, resourceGroupName, err)
		} else {
			log.Printf("DNS Zone Contributor role assigned: subscription=%s, resource_group=%s", subscriptionID, resourceGroupName)
		}
	}

	keyVaultName := viper.GetString(constants.KeyVaultName)
	keyVaultResourceGroup := viper.GetString(constants.KeyVaultRG)

	if keyVaultName == "" || keyVaultResourceGroup == "" {
		log.Printf("Key Vault name or Resource Group not provided; skipping Key Vault role assignment")
	} else {
		if err := assignKeyVaultCertificatesOfficerRole(spInfo, subscriptionID, keyVaultName, keyVaultResourceGroup); err != nil {
			log.Printf("Key Vault Certificates Officer role assignment failed: subscription=%s, key_vault=%s, error=%v", subscriptionID, keyVaultName, err)
		} else {
			log.Printf("Key Vault Certificates Officer role assigned: subscription=%s, key_vault=%s", subscriptionID, keyVaultName)
		}
	}

	return spInfo, nil
}

func assignDNSZoneContributorRole(spInfo *types.ServicePrincipalInfo, subscriptionID string, resourceGroupName string) error {
	// DNS Zone Contributor role ID
	dnsZoneContributorRoleID := "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/" + DNSZoneContributorRoleID

	// Resource group scope
	scope := "/subscriptions/" + subscriptionID + "/resourceGroups/" + resourceGroupName

	// Generate a unique role assignment ID
	roleAssignmentID := uuid.New().String()

	roleAssignmentProperties := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: &dnsZoneContributorRoleID,
			PrincipalID:      &spInfo.ServicePrincipalID,
		},
	}

	// Retry role assignment if PrincipalNotFound error occurs
	maxRetries := 5
	waitTime := time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		_, err := azure.GetAuthClient().Create(context.Background(), scope, roleAssignmentID, roleAssignmentProperties, nil)
		if err == nil {
			if attempt > 1 {
				log.Printf("DNS Zone Contributor role assignment succeeded after %d attempt(s)", attempt)
			}
			return nil
		}

		// Check if this is a PrincipalNotFound error
		if strings.Contains(err.Error(), "PrincipalNotFound") || strings.Contains(err.Error(), "does not exist") {
			if attempt == maxRetries {
				return fmt.Errorf("failed to create role assignment after %d attempts, principal not found: %v", maxRetries, err)
			}

			log.Printf("Principal not found for DNS role assignment (attempt %d/%d), waiting %v before retry",
				attempt, maxRetries, waitTime)
			time.Sleep(waitTime)
			waitTime *= 2 // Double the wait time for next attempt
			continue
		}

		// For other errors, don't retry
		return fmt.Errorf("failed to create role assignment: %v", err)
	}

	return nil
}

func assignKeyVaultCertificatesOfficerRole(spInfo *types.ServicePrincipalInfo, subscriptionID string, keyVaultName, keyVaultResourceGroup string) error {
	// Key Vault Certificates Officer role ID
	keyVaultCertificatesOfficerRoleID := "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/" + KeyVaultCertificatesOfficerRoleID

	// Key Vault scope
	scope := "/subscriptions/" + subscriptionID + "/resourceGroups/" + keyVaultResourceGroup + "/providers/Microsoft.KeyVault/vaults/" + keyVaultName

	// Generate a unique role assignment ID
	roleAssignmentID := uuid.New().String()

	roleAssignmentProperties := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: &keyVaultCertificatesOfficerRoleID,
			PrincipalID:      &spInfo.ServicePrincipalID,
		},
	}

	// Retry role assignment if PrincipalNotFound error occurs
	maxRetries := 5
	waitTime := time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		_, err := azure.GetAuthClient().Create(context.Background(), scope, roleAssignmentID, roleAssignmentProperties, nil)
		if err == nil {
			if attempt > 1 {
				log.Printf("Key Vault Certificates Officer role assignment succeeded after %d attempt(s)", attempt)
			}
			return nil
		}

		// Check if this is a PrincipalNotFound error
		if strings.Contains(err.Error(), "PrincipalNotFound") || strings.Contains(err.Error(), "does not exist") {
			if attempt == maxRetries {
				return fmt.Errorf("failed to create role assignment after %d attempts, principal not found: %v", maxRetries, err)
			}

			log.Printf("Principal not found for Key Vault role assignment (attempt %d/%d), waiting %v before retry",
				attempt, maxRetries, waitTime)
			time.Sleep(waitTime)
			waitTime *= 2 // Double the wait time for next attempt
			continue
		}

		// For other errors, don't retry
		return fmt.Errorf("failed to create role assignment: %v", err)
	}

	return nil
}

// setupCertificateAuth generates a self-signed certificate and configures certificate-based authentication
func setupCertificateAuth(applicationID, privateKeyPath, certificatePath string) error {
	// Generate self-signed certificate and private key
	cert, privateKey, err := generateSelfSignedCertificate(applicationID)
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate: %v", err)
	}

	// Save private key to file
	privateKeyPEM := encodePrivateKeyToPEM(privateKey)
	err = os.WriteFile(privateKeyPath, privateKeyPEM, 0600)
	if err != nil {
		return fmt.Errorf("failed to write private key file: %v", err)
	}

	// Save certificate to file
	certPEM := encodeCertificateToPEM(cert)
	err = os.WriteFile(certificatePath, certPEM, 0644)
	if err != nil {
		return fmt.Errorf("failed to write certificate file: %v", err)
	}

	// Upload the certificate to Azure AD Application to enable certificate authentication
	keyCredential := models.NewKeyCredential()

	// Set certificate data (raw DER bytes)
	keyCredential.SetKey(cert.Raw)

	// Set required properties for certificate authentication
	displayName := "Generated certificate by azure-ssl-certificate-provisioner"
	keyCredential.SetDisplayName(&displayName)

	// Set the type to AsymmetricX509Cert as required by Azure AD
	credType := "AsymmetricX509Cert"
	keyCredential.SetTypeEscaped(&credType)

	// Set usage for certificate authentication
	usage := "Verify"
	keyCredential.SetUsage(&usage)

	// Set start and end dates from the certificate
	startDateTime := cert.NotBefore
	endDateTime := cert.NotAfter
	keyCredential.SetStartDateTime(&startDateTime)
	keyCredential.SetEndDateTime(&endDateTime)

	log.Printf("Certificate valid from: %s to %s", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	// Add a small delay to ensure application is fully created
	time.Sleep(2 * time.Second)

	// Try to update the application's keyCredentials directly instead of using AddKey
	existingApp, err := azure.GetGraphClient().Applications().ByApplicationId(applicationID).Get(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to retrieve application for certificate update (appId: %s): %v", applicationID, err)
	}

	// Get existing keyCredentials and append the new one
	existingKeyCreds := existingApp.GetKeyCredentials()
	if existingKeyCreds == nil {
		existingKeyCreds = []models.KeyCredentialable{}
	}
	updatedKeyCreds := append(existingKeyCreds, keyCredential)

	// Update the application with the new keyCredentials
	updateApp := models.NewApplication()
	updateApp.SetKeyCredentials(updatedKeyCreds)

	_, err = azure.GetGraphClient().Applications().ByApplicationId(applicationID).Patch(context.Background(), updateApp, nil)
	if err != nil {
		return fmt.Errorf("failed to upload certificate to Azure AD application (appId: %s): %v", applicationID, err)
	}

	log.Printf("Certificate successfully uploaded to Azure AD application")

	return nil
}

// generateSelfSignedCertificate generates a self-signed certificate and private key
func generateSelfSignedCertificate(applicationID string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("azure-ssl-cert-provisioner-%s", applicationID),
			Organization: []string{"Azure SSL Certificate Provisioner"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, privateKey, nil
}

// encodePrivateKeyToPEM encodes a private key to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	return privateKeyPEM
}

// encodeCertificateToPEM encodes a certificate to PEM format
func encodeCertificateToPEM(cert *x509.Certificate) []byte {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return certPEM
}
