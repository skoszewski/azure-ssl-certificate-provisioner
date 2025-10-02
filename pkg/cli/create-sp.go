package cli

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/types"
	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/constants"
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
	cmd.Flags().Bool(constants.NoRoles, false, "Disable all role assignments even if other role flags are specified")
	cmd.Flags().Bool(constants.DryRun, false, "Output the service principal details without creating it")
	cmd.Flags().Bool(constants.UseCertAuth, false, "Use certificate-based authentication (expects {client-id}.key and {client-id}.crt files)")
	cmd.Flags().String(constants.Shell, utilities.GetDefaultShell(), "Shell type for output template (bash, powershell)")

	viper.BindPFlag(constants.Name, createSPCmd.Flags().Lookup(constants.Name))
	viper.BindPFlag(constants.TenantID, createSPCmd.Flags().Lookup(constants.TenantID))
	viper.BindPFlag(constants.SubscriptionID, createSPCmd.Flags().Lookup(constants.SubscriptionID))
	viper.BindPFlag(constants.ResourceGroupName, createSPCmd.Flags().Lookup(constants.ResourceGroupName))
	viper.BindPFlag(constants.KeyVaultName, createSPCmd.Flags().Lookup(constants.KeyVaultName))
	viper.BindPFlag(constants.KeyVaultRG, createSPCmd.Flags().Lookup(constants.KeyVaultRG))
	viper.BindPFlag(constants.NoRoles, createSPCmd.Flags().Lookup(constants.NoRoles))
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

	if viper.GetString(constants.SubscriptionID) == "" {
		log.Fatalf("Subscription ID is required. Use --%s flag.", constants.SubscriptionID)
	}

	return nil
}

// createSPCmdRun executes the service principal creation logic
func createSPCmdRun(cmd *cobra.Command, args []string) {
	displayName := viper.GetString(constants.Name)
	tenantID := viper.GetString(constants.TenantID)
	subscriptionID := viper.GetString(constants.SubscriptionID)
	resourceGroup := viper.GetString(constants.ResourceGroupName)
	keyVaultName := viper.GetString(constants.KeyVaultName)
	keyVaultResourceGroup := viper.GetString(constants.KeyVaultRG)
	noRoles := viper.GetBool(constants.NoRoles)
	useCertAuth := viper.GetBool(constants.UseCertAuth)
	shell := viper.GetString(constants.Shell)

	if resourceGroup != "" {
		utilities.LogVerbose("DNS role assignment: resource_group=%s", resourceGroup)
	}

	// Automatically assign DNS role if resource group is provided (unless --no-roles is specified)
	assignRole := resourceGroup != "" && !noRoles

	// Log certificate authentication mode
	if useCertAuth {
		utilities.LogDefault("Certificate-based authentication enabled")
	}

	// Override role assignments if --no-roles is specified
	if noRoles {
		assignRole = false
		keyVaultName = ""
		keyVaultResourceGroup = ""
		utilities.LogDefault("Role assignments disabled by --%s flag", constants.NoRoles)
	} else {
		// If kv-resource-group is not specified but kv-name is, use resource-group as fallback
		if keyVaultName != "" && keyVaultResourceGroup == "" {
			keyVaultResourceGroup = resourceGroup
			if keyVaultResourceGroup == "" {
				log.Fatalf("Resource group is required when assigning Key Vault role. Use --%s or --%s flag.", constants.ResourceGroupName, constants.KeyVaultRG)
			}
			utilities.LogDefault("Key Vault role assignment: resource_group=%s, key_vault=%s", keyVaultResourceGroup, keyVaultName)
		}
	}

	var spInfo *types.ServicePrincipalInfo
	if !viper.GetBool(constants.DryRun) {
		utilities.LogDefault("Service principal creation started: %s", displayName)

		// Create Azure clients
		azureClients, err := azure.NewClients(subscriptionID, "https://dummy.vault.azure.net/") // Dummy URL since we don't need KV client here
		if err != nil {
			log.Fatalf("Failed to create Azure clients: %v", err)
		}

		spInfo, err = azureClients.CreateServicePrincipal(displayName, tenantID, subscriptionID, assignRole, resourceGroup, keyVaultName, keyVaultResourceGroup, noRoles, useCertAuth)
		if err != nil {
			log.Fatalf("Failed to create service principal: %v", err)
		}

		utilities.LogDefault("Service principal created: application_id=%s, client_id=%s, service_principal_id=%s", spInfo.ApplicationID, spInfo.ClientID, spInfo.ServicePrincipalID)
	} else {
		utilities.LogDefault("Dry run mode: service principal not created")
		spInfo = &types.ServicePrincipalInfo{
			ApplicationID:      "your-application-id",
			ClientID:           "your-client-id",
			ClientSecret:       "your-client-secret",
			ServicePrincipalID: "your-service-principal-id",
			SubscriptionID:     subscriptionID,
			TenantID:           tenantID,
			UseCertAuth:        useCertAuth,
		}
	}

	GenerateServicePrincipalTemplate(spInfo, shell, keyVaultName, keyVaultResourceGroup)
}
