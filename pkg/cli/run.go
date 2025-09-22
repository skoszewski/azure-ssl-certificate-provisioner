package cli

import (
	"context"
	"log"
	"strings"

	"github.com/go-acme/lego/v4/lego"
	legoAzure "github.com/go-acme/lego/v4/providers/dns/azure"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/pkg/acme"
	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/certificate"
	"azure-ssl-certificate-provisioner/pkg/config"
)

// createRunCommand creates the run command
func (c *Commands) createRunCommand() *cobra.Command {
	var runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the SSL certificate provisioner",
		Long:  `Scan Azure DNS zones and provision SSL certificates for records marked with ACME metadata.`,
		Run: func(cmd *cobra.Command, args []string) {
			c.runCertificateProvisioner()
		},
	}

	// Configure flags for run command
	runCmd.Flags().StringSliceP("zones", "z", nil, "DNS zone(s) to search for records (can be used multiple times). If omitted, all zones in the resource group will be scanned")
	runCmd.Flags().StringP("subscription", "s", "", "Azure subscription ID")
	runCmd.Flags().StringP("resource-group", "g", "", "Azure resource group name")
	runCmd.Flags().Bool("staging", true, "Use Let's Encrypt staging environment")
	runCmd.Flags().IntP("expire-threshold", "t", 7, "Certificate expiration threshold in days")
	runCmd.Flags().StringP("email", "e", "", "Email address for ACME account registration (required)")

	// Mark required flags
	runCmd.MarkFlagRequired("subscription")
	runCmd.MarkFlagRequired("resource-group")
	runCmd.MarkFlagRequired("email")

	return runCmd
}

// runCertificateProvisioner executes the main certificate provisioning logic
func (c *Commands) runCertificateProvisioner() {
	ctx := context.Background()

	// Get configuration values
	zones := viper.GetStringSlice("zones")
	subscriptionId := viper.GetString("subscription")
	resourceGroupName := viper.GetString("resource-group")
	staging := viper.GetBool("staging")
	expireThreshold := viper.GetInt("expire-threshold")
	email := viper.GetString("email")

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
	if err := config.ValidateRequiredEnvVars(); err != nil {
		log.Fatalf("Environment validation failed: %v", err)
	}

	vaultURL := viper.GetString("key-vault-url")

	// Create Azure clients
	azureClients, err := azure.NewClients(subscriptionId, vaultURL)
	if err != nil {
		log.Fatalf("Failed to create Azure clients: %v", err)
	}

	// Configure ACME server based on staging flag
	var serverURL string
	if staging {
		serverURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		log.Printf("Using Let's Encrypt staging environment")
	} else {
		serverURL = "https://acme-v02.api.letsencrypt.org/directory"
		log.Printf("Using Let's Encrypt production environment")
	}

	// Load or create ACME account with persistence
	user, err := acme.LoadOrCreateAccount(email, serverURL)
	if err != nil {
		log.Fatalf("failed to load or create ACME account: %v", err)
	}

	config := lego.NewConfig(user)
	if config == nil {
		log.Fatalf("failed to create ACME config")
	}

	config.CADirURL = serverURL

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

	// Only register if we don't have existing registration
	if user.Registration == nil {
		if err := acme.RegisterAccount(user, acmeClient); err != nil {
			log.Fatalf("Failed to register ACME account: %v", err)
		}

		// Save the account data for future runs
		if err := acme.SaveAccountData(user, serverURL); err != nil {
			log.Printf("Warning: Failed to save account registration: %v", err)
		} else {
			log.Printf("Saved ACME account registration for future use")
		}
	} else {
		log.Printf("Using existing ACME account registration for %s", user.Email)
	}

	// Create certificate handler
	certHandler := certificate.NewHandler(acmeClient, azureClients.KVCert)

	// Determine which zones to process
	var zonesToProcess []string
	if len(zones) == 0 {
		// If no zones specified, get all zones from the resource group
		log.Printf("No zones specified, scanning all DNS zones in resource group: %s", resourceGroupName)
		zonesPager := azureClients.DNSZones.NewListByResourceGroupPager(resourceGroupName, nil)

		for zonesPager.More() {
			zonesPage, err := zonesPager.NextPage(ctx)
			if err != nil {
				log.Fatalf("failed to list DNS zones in resource group %s: %v", resourceGroupName, err)
			}

			for _, zone := range zonesPage.Value {
				if zone != nil && zone.Name != nil {
					zonesToProcess = append(zonesToProcess, *zone.Name)
				}
			}
		}

		if len(zonesToProcess) == 0 {
			log.Printf("No DNS zones found in resource group: %s", resourceGroupName)
			return
		}

		log.Printf("Found %d DNS zone(s) to process: %v", len(zonesToProcess), zonesToProcess)
	} else {
		zonesToProcess = zones
		log.Printf("Processing specified zones: %v", zonesToProcess)
	}

	// Process zones
	for _, zone := range zonesToProcess {
		log.Printf("Processing DNS zone: %s", zone)
		pager := azureClients.DNS.NewListAllByDNSZonePager(resourceGroupName, zone, nil)

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
				certHandler.ProcessFQDN(ctx, fqdn, expireThreshold)
			}
		}
	}
}
