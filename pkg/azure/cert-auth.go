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
	"time"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

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
	existingApp, err := GetGraphClient().Applications().ByApplicationId(applicationID).Get(context.Background(), nil)
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

	_, err = GetGraphClient().Applications().ByApplicationId(applicationID).Patch(context.Background(), updateApp, nil)
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
