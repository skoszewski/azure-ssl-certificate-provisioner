package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"crypto"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	legoAzure "github.com/go-acme/lego/v4/providers/dns/azure"
	"github.com/go-acme/lego/v4/registration"
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

func daysUntilExpiry(expiry time.Time) int {
	return int(time.Until(expiry).Hours() / 24)
}

func certNameForFQDN(fqdn string) string {
	return "cert-" + strings.ReplaceAll(fqdn, ".", "-")
}

func handleFQDN(ctx context.Context, fqdn string, acmeClient *lego.Client, kvCertClient *azcertificates.Client) error {
	certName := certNameForFQDN(fqdn)
	log.Printf("Checking %s...", fqdn)

	resp, err := kvCertClient.GetCertificate(ctx, certName, "", nil)
	daysLeft := 0
	if err == nil && resp.Attributes != nil && resp.Attributes.Expires != nil {
		expiry := *resp.Attributes.Expires
		daysLeft = daysUntilExpiry(expiry)
		log.Printf("Existing certificate expires on %s (%d days left)", expiry.Format(time.RFC3339), daysLeft)
	} else {
		log.Printf("Certificate does not exist in Key Vault")
	}

	if daysLeft > 7 {
		log.Printf("Skipping renewal; certificate still valid")
		return nil
	}

	legoReq := certificate.ObtainRequest{
		Domains: []string{fqdn},
		Bundle:  true,
	}

	legoCert, err := acmeClient.Certificate.Obtain(legoReq)
	if err != nil {
		log.Printf("ERROR: failed to obtain certificate for %s: %v", fqdn, err)
		return nil
	}

	block, _ := pem.Decode(legoCert.Certificate)
	if block == nil {
		log.Printf("ERROR: unable to parse PEM for %s", fqdn)
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("ERROR: unable to parse certificate for %s: %v", fqdn, err)
		return nil
	}

	log.Printf("Obtained new certificate expiring on %s", cert.NotAfter.Format(time.RFC3339))

	// Use modern PKCS12 encoding for better security
	pfxData, err := pkcs12.Modern.Encode(legoCert.PrivateKey, cert, nil, "")
	if err != nil {
		log.Printf("      ERROR: PKCS#12 encoding failed for %s: %v", fqdn, err)
		return nil
	}

	// Azure Key Vault expects base64-encoded certificate data
	base64Cert := base64.StdEncoding.EncodeToString(pfxData)
	_, err = kvCertClient.ImportCertificate(ctx, certName, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &base64Cert,
	}, nil)
	if err != nil {
		log.Printf("ERROR: failed to import certificate for %s into Key Vault: %v", fqdn, err)
		return nil
	}

	log.Printf("Imported certificate %s into Key Vault", certName)
	return nil
}

func main() {
	ctx := context.Background()

	var domains []string
	var subscriptionId string
	var resourceGroupName string

	flag.Func("d", "domain to search for records", func(s string) error {
		domains = append(domains, s)
		return nil
	})

	flag.StringVar(&subscriptionId, "s", os.Getenv("AZURE_SUBSCRIPTION_ID"), "Subscription ID")
	flag.StringVar(&resourceGroupName, "g", os.Getenv("RESOURCE_GROUP_NAME"), "Resource Group Name")

	// Parse flags
	flag.Parse()

	if len(domains) == 0 {
		log.Fatalf("No domains were specified. Use -d flag at least once.")
	}

	if subscriptionId == "" {
		log.Fatalf("Subscription ID not specified.")
	}

	if resourceGroupName == "" {
		log.Fatalf("Resource Group Name not specified.")
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

	vaultURL := os.Getenv("AZURE_KEY_VAULT_URL")
	if vaultURL == "" {
		log.Fatalf("KEY_VAULT_URL environment variable not set")
	}

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
				if err := handleFQDN(ctx, fqdn, acmeClient, kvCertClient); err != nil {
					log.Printf("failed to issue, renew or save a certificate for the FQDN %s: %v", fqdn, err)
				}
			}
		}
	}
}
