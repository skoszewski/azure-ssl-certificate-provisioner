package cli

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/azure"
)

// createSPCommand creates the create-sp command
func createSPCommand() *cobra.Command {
	var createSPCmd = &cobra.Command{
		Use:   "create-sp",
		Short: "Create Azure service principal for SSL certificate provisioning",
		Long:  `Create an Azure AD application and service principal with optional role assignments for DNS and Key Vault access.`,
		Run: func(cmd *cobra.Command, args []string) {
			runCreateServicePrincipal()
		},
	}

	createSPCmd.Flags().StringP("name", "n", "", "Display name for the Azure AD application (required)")
	createSPCmd.Flags().StringP("tenant-id", "t", "", "Azure tenant ID (required)")
	createSPCmd.Flags().StringP("subscription-id", "s", "", "Azure subscription ID (required)")
	createSPCmd.Flags().StringP("resource-group", "g", "", "Resource group name for DNS Zone Contributor role assignment")
	createSPCmd.Flags().StringP("kv-name", "", "", "Key Vault name for Certificates Officer role assignment")
	createSPCmd.Flags().StringP("kv-resource-group", "", "", "Resource group name for the Key Vault")
	createSPCmd.Flags().Bool("no-roles", false, "Disable all role assignments even if other role flags are specified")
	createSPCmd.Flags().Bool("use-cert-auth", false, "Use certificate-based authentication (expects {client-id}.key and {client-id}.crt files)")
	createSPCmd.Flags().StringP("shell", "", utilities.GetDefaultShell(), "Shell type for output template (bash, powershell)")

	// Mark required flags
	createSPCmd.MarkFlagRequired("name")
	createSPCmd.MarkFlagRequired("tenant-id")
	createSPCmd.MarkFlagRequired("subscription-id")

	return createSPCmd
}

// runCreateServicePrincipal executes the service principal creation logic
func runCreateServicePrincipal() {
	displayName := viper.GetString("sp-name")
	tenantID := viper.GetString("azure-tenant-id")
	subscriptionID := viper.GetString("subscription")
	resourceGroup := viper.GetString("resource-group")
	keyVaultName := viper.GetString("kv-name")
	keyVaultResourceGroup := viper.GetString("kv-resource-group")
	noRoles := viper.GetBool("sp-no-roles")
	useCertAuth := viper.GetBool("sp-use-cert-auth")
	shell := viper.GetString("shell")

	// Automatically assign DNS role if resource group is provided (unless --no-roles is specified)
	assignRole := resourceGroup != "" && !noRoles

	if displayName == "" {
		log.Fatalf("Display name is required. Use --name flag.")
	}

	if tenantID == "" {
		log.Fatalf("Tenant ID is required. Use --tenant-id flag.")
	}

	if subscriptionID == "" {
		log.Fatalf("Subscription ID is required. Use --subscription-id flag.")
	}

	// Log certificate authentication mode
	if useCertAuth {
		utilities.LogDefault("Certificate-based authentication enabled")
	}

	// Override role assignments if --no-roles is specified
	if noRoles {
		assignRole = false
		keyVaultName = ""
		keyVaultResourceGroup = ""
		utilities.LogDefault("Role assignments disabled by --no-roles flag")
	} else {
		// If kv-resource-group is not specified but kv-name is, use resource-group as fallback
		if keyVaultName != "" && keyVaultResourceGroup == "" {
			keyVaultResourceGroup = resourceGroup
			if keyVaultResourceGroup == "" {
				log.Fatalf("Resource group is required when assigning Key Vault role. Use --resource-group or --kv-resource-group flag.")
			}
			utilities.LogDefault("Key Vault role assignment: resource_group=%s, key_vault=%s", keyVaultResourceGroup, keyVaultName)
		}
	}

	utilities.LogDefault("Service principal creation started: %s", displayName)

	// Create Azure clients
	azureClients, err := azure.NewClients(subscriptionID, "https://dummy.vault.azure.net/") // Dummy URL since we don't need KV client here
	if err != nil {
		log.Fatalf("Failed to create Azure clients: %v", err)
	}

	spInfo, err := azureClients.CreateServicePrincipal(displayName, tenantID, subscriptionID, assignRole, resourceGroup, keyVaultName, keyVaultResourceGroup, noRoles, useCertAuth)
	if err != nil {
		log.Fatalf("Failed to create service principal: %v", err)
	}

	utilities.LogDefault("Service principal created: application_id=%s, client_id=%s, service_principal_id=%s", spInfo.ApplicationID, spInfo.ClientID, spInfo.ServicePrincipalID)

	GenerateServicePrincipalTemplate(spInfo, shell, keyVaultName, keyVaultResourceGroup)
}
