package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/internal/utilities"
	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/constants"
)

var deleteSPCmd = &cobra.Command{
	Use:   "delete-sp",
	Short: "Delete Azure AD Application and Service Principal with role cleanup",
	Long: `Delete an Azure AD Application and Service Principal by client ID.
This command will:
1. Find the application and service principal by client ID
2. Remove role assignments from Key Vault and resource groups
3. Delete the service principal
4. Delete the Azure AD application
5. Clean up local certificate files`,
	RunE: deleteSPCmdRunE,
}

func deleteSPCmdSetup(cmd *cobra.Command) {
	// Add flags
	cmd.Flags().StringP(constants.ClientID, "c", "", "Client ID (App ID) of the Azure AD application to delete (required)")
	cmd.Flags().String(constants.TenantID, "", "Azure AD tenant ID (optional, will use default if not specified)")
	cmd.Flags().StringP(constants.SubscriptionID, "s", "", "Azure subscription ID (required for role assignment cleanup)")

	viper.BindPFlag(constants.ClientID, deleteSPCmd.Flags().Lookup(constants.ClientID))
	viper.BindPFlag(constants.AzureTenantID, deleteSPCmd.Flags().Lookup(constants.TenantID))
	viper.BindPFlag(constants.SubscriptionID, deleteSPCmd.Flags().Lookup(constants.SubscriptionID))
}

// deleteSPCmdRunE executes the delete-sp command
func deleteSPCmdRunE(cmd *cobra.Command, args []string) error {
	clientID := viper.GetString(constants.ClientID)
	tenantID := viper.GetString(constants.AzureTenantID)
	subscriptionID := viper.GetString(constants.SubscriptionID)

	if clientID == "" {
		return fmt.Errorf("client-id is required")
	}

	if subscriptionID == "" {
		return fmt.Errorf("%s is required for role assignment cleanup", constants.SubscriptionID)
	}

	utilities.LogDefault("Service principal deletion started: %s", clientID)

	// Delete the service principal and application with role cleanup
	err := azure.DeleteServicePrincipalByClientID(clientID, subscriptionID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete service principal: %v", err)
	}

	utilities.LogDefault("Service principal and application deleted successfully: %s", clientID)
	return nil
}
