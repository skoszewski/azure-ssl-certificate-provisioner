package certificate

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"software.sslmate.com/src/go-pkcs12"
)

// Handler handles certificate operations
type Handler struct {
	acmeClient   *lego.Client
	kvCertClient *azcertificates.Client
}

// NewHandler creates a new certificate handler
func NewHandler(acmeClient *lego.Client, kvCertClient *azcertificates.Client) *Handler {
	return &Handler{
		acmeClient:   acmeClient,
		kvCertClient: kvCertClient,
	}
}

// ProcessFQDN handles certificate provisioning for a given FQDN
func (h *Handler) ProcessFQDN(ctx context.Context, fqdn string, expireThreshold int) {
	certName := "cert-" + strings.ReplaceAll(fqdn, ".", "-")
	log.Printf("Checking %s...", fqdn)

	resp, err := h.kvCertClient.GetCertificate(ctx, certName, "", nil)
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

	legoCert, err := h.acmeClient.Certificate.Obtain(legoReq)
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
	_, err = h.kvCertClient.ImportCertificate(ctx, certName, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &base64Cert,
	}, nil)
	if err != nil {
		log.Printf("ERROR: failed to import certificate for %s into Key Vault: %v", fqdn, err)
		return
	}

	log.Printf("Imported certificate %s into Key Vault", certName)
}
