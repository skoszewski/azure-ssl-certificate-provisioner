package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/pkg/azure"
)

// createDeleteServicePrincipalCommand creates the delete-sp command
func (c *Commands) createDeleteServicePrincipalCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete-sp",
		Short: "Delete Azure AD Application and Service Principal with role cleanup",
		Long: `Delete an Azure AD Application and Service Principal by client ID.
This command will:
1. Find the application and service principal by client ID
2. Remove role assignments from Key Vault and resource groups
3. Delete the service principal
4. Delete the Azure AD application
5. Clean up local certificate files`,
		RunE: c.runDeleteServicePrincipal,
	}

	// Add flags
	cmd.Flags().StringP("client-id", "c", "", "Client ID (App ID) of the Azure AD application to delete (required)")
	cmd.Flags().String("tenant-id", "", "Azure AD tenant ID (optional, will use default if not specified)")
	cmd.Flags().StringP("subscription-id", "s", "", "Azure subscription ID (required for role assignment cleanup)")

	// Mark required flags
	cmd.MarkFlagRequired("client-id")
	cmd.MarkFlagRequired("subscription-id")

	return cmd
}

// runDeleteServicePrincipal executes the delete-sp command
func (c *Commands) runDeleteServicePrincipal(cmd *cobra.Command, args []string) error {
	clientID := viper.GetString("delete-sp-client-id")
	tenantID := viper.GetString("delete-sp-tenant-id")
	subscriptionID := viper.GetString("delete-sp-subscription-id")

	if clientID == "" {
		return fmt.Errorf("client-id is required")
	}

	if subscriptionID == "" {
		return fmt.Errorf("subscription-id is required for role assignment cleanup")
	}

	log.Printf("Service principal deletion started: %s", clientID)

	// Create Azure clients
	clients, err := azure.NewClients(subscriptionID, "")
	if err != nil {
		return fmt.Errorf("failed to create Azure clients: %v", err)
	}

	// Delete the service principal and application with role cleanup
	err = clients.DeleteServicePrincipalByClientID(clientID, subscriptionID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete service principal: %v", err)
	}

	log.Printf("Service principal and application deleted successfully: %s", clientID)
	return nil
}
