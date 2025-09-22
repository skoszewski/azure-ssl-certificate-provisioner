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

// Commands holds all CLI commands
type Commands struct {
	templateGen *TemplateGenerator
}

// NewCommands creates a new commands instance
func NewCommands() *Commands {
	return &Commands{
		templateGen: NewTemplateGenerator(),
	}
}

// CreateRootCommand creates the root cobra command
func (c *Commands) CreateRootCommand() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "azure-ssl-certificate-provisioner",
		Short: "Automatically provision SSL certificates from Let's Encrypt for Azure DNS zones",
		Long: `Azure SSL Certificate Provisioner scans Azure DNS zones for records marked with 
ACME metadata and automatically provisions SSL certificates using Let's Encrypt, 
storing them in Azure Key Vault.`,
	}

	// Create subcommands
	runCmd := c.createRunCommand()
	envCmd := c.createEnvironmentCommand()
	createSPCmd := c.createServicePrincipalCommand()

	// Configure flag bindings
	c.setupFlagBindings(runCmd, createSPCmd)

	// Add subcommands to root command
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(createSPCmd)

	return rootCmd
}

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
	runCmd.Flags().StringSliceP("domains", "d", nil, "Domain(s) to search for records (can be used multiple times)")
	runCmd.Flags().StringP("subscription", "s", "", "Azure subscription ID")
	runCmd.Flags().StringP("resource-group", "g", "", "Azure resource group name")
	runCmd.Flags().Bool("staging", true, "Use Let's Encrypt staging environment")
	runCmd.Flags().IntP("expire-threshold", "t", 7, "Certificate expiration threshold in days")
	runCmd.Flags().StringP("email", "e", "", "Email address for ACME account registration (required)")

	// Mark required flags
	runCmd.MarkFlagRequired("domains")
	runCmd.MarkFlagRequired("subscription")
	runCmd.MarkFlagRequired("resource-group")
	runCmd.MarkFlagRequired("email")

	return runCmd
}

func (c *Commands) createEnvironmentCommand() *cobra.Command {
	var envCmd = &cobra.Command{
		Use:   "environment",
		Short: "Generate environment variable templates",
		Long:  `Generate Bash or PowerShell environment variable templates for required configuration.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Default to bash if no subcommand is specified
			c.templateGen.GenerateEnvironmentTemplate("bash")
		},
	}

	// Create bash subcommand
	bashCmd := &cobra.Command{
		Use:   "bash",
		Short: "Generate Bash environment variable template",
		Run: func(cmd *cobra.Command, args []string) {
			c.templateGen.GenerateEnvironmentTemplate("bash")
		},
	}

	// Create PowerShell subcommand
	powershellCmd := &cobra.Command{
		Use:     "powershell",
		Aliases: []string{"ps", "ps1"},
		Short:   "Generate PowerShell environment variable template",
		Run: func(cmd *cobra.Command, args []string) {
			c.templateGen.GenerateEnvironmentTemplate("powershell")
		},
	}

	envCmd.AddCommand(bashCmd)
	envCmd.AddCommand(powershellCmd)
	return envCmd
}

func (c *Commands) createServicePrincipalCommand() *cobra.Command {
	var createSPCmd = &cobra.Command{
		Use:   "create-service-principal",
		Short: "Create Azure service principal for SSL certificate provisioning",
		Long:  `Create an Azure AD application and service principal with optional DNS Zone Contributor role assignment.`,
		Run: func(cmd *cobra.Command, args []string) {
			c.runCreateServicePrincipal()
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

	// Mark required flags
	createSPCmd.MarkFlagRequired("name")
	createSPCmd.MarkFlagRequired("tenant-id")
	createSPCmd.MarkFlagRequired("subscription-id")

	return createSPCmd
}

func (c *Commands) setupFlagBindings(runCmd, createSPCmd *cobra.Command) {
	// Bind flags to viper for run command
	viper.BindPFlag("domains", runCmd.Flags().Lookup("domains"))
	viper.BindPFlag("subscription", runCmd.Flags().Lookup("subscription"))
	viper.BindPFlag("resource-group", runCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("staging", runCmd.Flags().Lookup("staging"))
	viper.BindPFlag("expire-threshold", runCmd.Flags().Lookup("expire-threshold"))
	viper.BindPFlag("email", runCmd.Flags().Lookup("email"))

	// Bind flags for create-service-principal command
	viper.BindPFlag("name", createSPCmd.Flags().Lookup("name"))
	viper.BindPFlag("tenant-id", createSPCmd.Flags().Lookup("tenant-id"))
	viper.BindPFlag("subscription-id", createSPCmd.Flags().Lookup("subscription-id"))
	viper.BindPFlag("assign-dns-role", createSPCmd.Flags().Lookup("assign-dns-role"))
	viper.BindPFlag("resource-group", createSPCmd.Flags().Lookup("resource-group"))
	viper.BindPFlag("kv-name", createSPCmd.Flags().Lookup("kv-name"))
	viper.BindPFlag("kv-resource-group", createSPCmd.Flags().Lookup("kv-resource-group"))
	viper.BindPFlag("shell", createSPCmd.Flags().Lookup("shell"))

	// Setup viper configuration
	config.SetupViper()
}

func (c *Commands) runCertificateProvisioner() {
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

	// Process domains
	for _, zone := range domains {
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

func (c *Commands) runCreateServicePrincipal() {
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

	// Create Azure clients
	azureClients, err := azure.NewClients(subscriptionID, "https://dummy.vault.azure.net/") // Dummy URL since we don't need KV client here
	if err != nil {
		log.Fatalf("Failed to create Azure clients: %v", err)
	}

	spInfo, err := azureClients.CreateServicePrincipal(displayName, tenantID, subscriptionID, assignRole, resourceGroup, keyVaultName, keyVaultResourceGroup)
	if err != nil {
		log.Fatalf("Failed to create service principal: %v", err)
	}

	log.Printf("Successfully created service principal!")
	log.Printf("Application ID: %s", spInfo.ApplicationID)
	log.Printf("Client ID: %s", spInfo.ClientID)
	log.Printf("Service Principal ID: %s", spInfo.ServicePrincipalID)

	c.templateGen.GenerateServicePrincipalTemplate(spInfo, shell, keyVaultName, keyVaultResourceGroup)
}
