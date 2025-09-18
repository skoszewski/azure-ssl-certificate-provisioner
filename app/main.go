package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"

	"crypto"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	legoAzure "github.com/go-acme/lego/v4/providers/dns/azure"
	"github.com/go-acme/lego/v4/registration"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
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

func handleFQDN(ctx context.Context, fqdn string, client *lego.Client) {

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
			}
		}
	}
}
