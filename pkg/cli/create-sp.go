package cli

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

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
	cmd.Flags().Bool(constants.DryRun, false, "Output the service principal details without creating it")
	cmd.Flags().Bool(constants.UseCertAuth, false, "Use certificate-based authentication (expects {client-id}.key and {client-id}.crt files)")
	cmd.Flags().String(constants.Shell, utilities.GetDefaultShell(), "Shell type for output template (bash, powershell)")

	viper.BindPFlag(constants.Name, createSPCmd.Flags().Lookup(constants.Name))
	viper.BindPFlag(constants.TenantID, createSPCmd.Flags().Lookup(constants.TenantID))
	viper.BindPFlag(constants.SubscriptionID, createSPCmd.Flags().Lookup(constants.SubscriptionID))
	viper.BindPFlag(constants.ResourceGroupName, createSPCmd.Flags().Lookup(constants.ResourceGroupName))
	viper.BindPFlag(constants.KeyVaultName, createSPCmd.Flags().Lookup(constants.KeyVaultName))
	viper.BindPFlag(constants.KeyVaultRG, createSPCmd.Flags().Lookup(constants.KeyVaultRG))
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

	return nil
}

// createSPCmdRun executes the service principal creation logic
func createSPCmdRun(cmd *cobra.Command, args []string) {
	displayName := viper.GetString(constants.Name)
	tenantID := viper.GetString(constants.TenantID)

	if viper.GetBool(constants.DryRun) {
		utilities.LogDefault("Dry run mode: service principal not created")
		return
	}

	utilities.LogDefault("Service principal creation started: %s", displayName)

	spInfo, err := azure.CreateServicePrincipal(displayName, tenantID)
	if err != nil {
		log.Fatalf("Failed to create service principal: %v", err)
	}

	utilities.LogDefault("Service principal created: application_id=%s, client_id=%s, service_principal_id=%s", spInfo.ApplicationID, spInfo.ClientID, spInfo.ServicePrincipalID)
}
