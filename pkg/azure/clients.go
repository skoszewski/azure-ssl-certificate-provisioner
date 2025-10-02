package azure

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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
)

func assignDNSZoneContributorRole(spInfo *ServicePrincipalInfo, subscriptionID string, resourceGroupName string) error {
	// DNS Zone Contributor role ID
	dnsZoneContributorRoleID := "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/befefa01-2a29-4197-83a8-272ff33ce314"

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
		_, err = GetAuthClient().Create(context.Background(), scope, roleAssignmentID, roleAssignmentProperties, nil)
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

func assignKeyVaultCertificatesOfficerRole(spInfo *ServicePrincipalInfo, subscriptionID string, keyVaultName, keyVaultResourceGroup string) error {
	// Key Vault Certificates Officer role ID
	keyVaultCertificatesOfficerRoleID := "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/a4417e6f-fecd-4de8-b567-7b0420556985"

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
		_, err = authClient.Create(context.Background(), scope, roleAssignmentID, roleAssignmentProperties, nil)
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
	existingApp, err := graphClient.Applications().ByApplicationId(applicationID).Get(context.Background(), nil)
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

	_, err = graphClient.Applications().ByApplicationId(applicationID).Patch(context.Background(), updateApp, nil)
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

// DeleteServicePrincipalByClientID deletes an Azure AD application and service principal by client ID
// It also removes all associated role assignments
func DeleteServicePrincipalByClientID(clientID, subscriptionID, tenantID string) error {
	ctx := context.Background()

	// Find the application by client ID
	log.Printf("Looking for Azure AD Application with client ID: '%s'", clientID)

	// Get application directly by client ID using filter
	filter := fmt.Sprintf("appId eq '%s'", clientID)
	apps, err := graphClient.Applications().Get(ctx, &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to get application by client ID: %v", err)
	}

	if apps.GetValue() == nil || len(apps.GetValue()) == 0 {
		return fmt.Errorf("no application found with client ID: '%s'", clientID)
	}

	targetApp := apps.GetValue()[0]
	var applicationID string
	if targetApp.GetId() != nil {
		applicationID = *targetApp.GetId()
	}

	log.Printf("Found application: %s (Client ID: %s)", applicationID, clientID)

	// Find the service principal associated with the application using filter
	spFilter := fmt.Sprintf("appId eq '%s'", clientID)
	servicePrincipalsResult, err := graphClient.ServicePrincipals().Get(ctx, &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
			Filter: &spFilter,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to get service principal by client ID: %v", err)
	}

	var servicePrincipalID string
	if servicePrincipalsResult.GetValue() != nil && len(servicePrincipalsResult.GetValue()) > 0 {
		if servicePrincipalsResult.GetValue()[0].GetId() != nil {
			servicePrincipalID = *servicePrincipalsResult.GetValue()[0].GetId()
		}
	}

	if servicePrincipalID != "" {
		log.Printf("Found service principal: %s", servicePrincipalID)

		// Remove role assignments before deleting the service principal
		if err := removeRoleAssignments(servicePrincipalID, subscriptionID); err != nil {
			log.Printf("Warning: Failed to remove some role assignments: %v", err)
		}

		// Delete the service principal
		log.Printf("Deleting service principal...")
		err = graphClient.ServicePrincipals().ByServicePrincipalId(servicePrincipalID).Delete(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to delete service principal: %v", err)
		}
		log.Printf("Service principal deleted successfully")
	} else {
		log.Printf("No service principal found for application: %s", clientID)
	}

	// Delete the application
	log.Printf("Deleting Azure AD application...")
	err = graphClient.Applications().ByApplicationId(applicationID).Delete(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to delete Azure AD application: %v", err)
	}
	log.Printf("Azure AD application deleted successfully")

	// Clean up local certificate files
	cleanupCertificateFiles(clientID)

	return nil
}

// removeRoleAssignments removes all role assignments for a service principal
func removeRoleAssignments(servicePrincipalID, subscriptionID string) error {
	if subscriptionID == "" {
		return fmt.Errorf("subscription ID is required for role assignment operations")
	}

	log.Printf("Removing role assignments for service principal %s in subscription %s", servicePrincipalID, subscriptionID)

	clientOptions := &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			APIVersion: "2022-04-01",
		},
	}
	authClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, credential, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to create authorization client: %v", err)
	}

	// List all role assignments for the subscription with filter by principal ID
	filter := fmt.Sprintf("principalId eq '%s'", servicePrincipalID)
	pager := authClient.NewListPager(&armauthorization.RoleAssignmentsClientListOptions{
		Filter: &filter,
	})

	var roleAssignmentsToDelete []struct {
		Name  string
		Scope string
	}

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return fmt.Errorf("failed to list role assignments: %v", err)
		}

		for _, assignment := range page.Value {
			if assignment.Properties != nil &&
				assignment.Properties.PrincipalID != nil &&
				*assignment.Properties.PrincipalID == servicePrincipalID {
				if assignment.Name != nil && assignment.Properties.Scope != nil {
					roleAssignmentsToDelete = append(roleAssignmentsToDelete, struct {
						Name  string
						Scope string
					}{
						Name:  *assignment.Name,
						Scope: *assignment.Properties.Scope,
					})
					log.Printf("Found role assignment to remove: %s at scope: %s", *assignment.Name, *assignment.Properties.Scope)
				}
			}
		}
	}

	// Delete each role assignment using the correct scope
	for _, assignment := range roleAssignmentsToDelete {
		_, err := authClient.Delete(context.Background(), assignment.Scope, assignment.Name, nil)
		if err != nil {
			log.Printf("Warning: Failed to delete role assignment %s at scope %s: %v", assignment.Name, assignment.Scope, err)
		} else {
			log.Printf("Role assignment removed: %s at scope: %s", assignment.Name, assignment.Scope)
		}
	}

	return nil
}

// cleanupCertificateFiles removes local certificate files for the given client ID
func cleanupCertificateFiles(clientID string) {
	privateKeyPath := fmt.Sprintf("%s.key", clientID)
	certificatePath := fmt.Sprintf("%s.crt", clientID)

	// Remove private key file
	if err := os.Remove(privateKeyPath); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Warning: Could not remove private key file %s: %v", privateKeyPath, err)
		}
	} else {
		log.Printf("Removed local certificate file: %s", privateKeyPath)
	}

	// Remove certificate file
	if err := os.Remove(certificatePath); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Warning: Could not remove certificate file %s: %v", certificatePath, err)
		}
	} else {
		log.Printf("Removed local certificate file: %s", certificatePath)
	}
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
