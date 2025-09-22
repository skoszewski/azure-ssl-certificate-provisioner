package cli

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/pkg/azure"
)

// createServicePrincipalCommand creates the create-service-principal command
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

// runCreateServicePrincipal executes the service principal creation logic
func (c *Commands) runCreateServicePrincipal() {
	displayName := viper.GetString("sp-name")
	tenantID := viper.GetString("sp-tenant-id")
	subscriptionID := viper.GetString("sp-subscription-id")
	assignRole := viper.GetBool("sp-assign-dns-role")
	resourceGroup := viper.GetString("sp-resource-group")
	keyVaultName := viper.GetString("sp-kv-name")
	keyVaultResourceGroup := viper.GetString("sp-kv-resource-group")
	shell := viper.GetString("sp-shell")

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
