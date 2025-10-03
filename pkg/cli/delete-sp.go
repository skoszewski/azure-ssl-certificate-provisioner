package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"azure-ssl-certificate-provisioner/pkg/azure"
	"azure-ssl-certificate-provisioner/pkg/constants"
	"azure-ssl-certificate-provisioner/pkg/utils"
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
	Run:     deleteSPCmdRun,
	PreRunE: deleteSPCmdPreRunE,
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

// Validate required flags before running the command, and let Cobra handle the error reporting
func deleteSPCmdPreRunE(cmd *cobra.Command, args []string) error {
	var err error
	// Validate required flags
	if viper.GetString(constants.ClientID) == "" {
		err = fmt.Errorf("client-id is required")
	}

	if viper.GetString(constants.SubscriptionID) == "" {
		err = fmt.Errorf("%s is required for role assignment cleanup", constants.SubscriptionID)
	}

	return err
}

// The command is supposed to be run interactively and not in scripts
// and will not use logging facilities but will honor verbose flag.
// It will also handle errors by itself and not return them.
func deleteSPCmdRun(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	// Disable usage on error
	cmd.SilenceUsage = true

	clientID := viper.GetString(constants.ClientID)
	subscriptionID := viper.GetString(constants.SubscriptionID)

	utils.PrintDefault("Service principal deletion started: %s", clientID)

	// Find the application by client ID
	utils.PrintDefault("Looking for Azure AD Application with client ID: '%s'", clientID)

	// Get application directly by client ID using filter
	filter := fmt.Sprintf("appId eq '%s'", clientID)
	collection, err := azure.GetGraphClient().Applications().Get(ctx, &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	})

	if err != nil {
		utils.PrintFatal("failed to search for an application by client ID: %v", err)
	}

	app := collection.GetValue()

	if len(app) != 1 {
		// If no application found or more than one found, log fatal error
		utils.PrintFatal("no application found with client ID or there are more than one: '%s'", clientID)
	}

	applicationID := *app[0].GetId()

	utils.PrintDefault("Found application: %s (Client ID: %s)", applicationID, clientID)

	// Find the service principal associated with the application using filter
	spFilter := fmt.Sprintf("appId eq '%s'", clientID)
	spCollection, err := azure.GetGraphClient().ServicePrincipals().Get(ctx, &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
			Filter: &spFilter,
		},
	})

	var spID string
	if err != nil {
		// If error occurs while getting service principal, log an error and continue
		utils.PrintError("failed to search for a service principal by client ID: %v", err)
	} else {
		sp := spCollection.GetValue()

		// If exactly one service principal found, proceed to delete
		if len(sp) != 1 {
			utils.PrintError("no service principal found with client ID or there are more than one: '%s'", clientID)
		} else {
			spID = *sp[0].GetId()

			if spID != "" {
				utils.PrintDefault("Found service principal: %s", spID)

				// Remove role assignments before deleting the service principal
				if err := removeRoleAssignments(spID, subscriptionID); err != nil {
					utils.PrintError("Warning: Failed to remove some role assignments: %v", err)
				}

				// Delete the service principal
				utils.PrintDefault("Deleting service principal...")
				err = azure.GetGraphClient().ServicePrincipals().ByServicePrincipalId(spID).Delete(ctx, nil)
				if err != nil {
					utils.PrintFatal("failed to delete service principal: %v", err)
				}
				utils.PrintDefault("Service principal deleted successfully")
			} else {
				utils.PrintWarning("No service principal found for application: %s", clientID)
			}
		}
	}

	// Delete the application
	utils.PrintDefault("Deleting Azure AD application...")
	err = azure.GetGraphClient().Applications().ByApplicationId(applicationID).Delete(ctx, nil)
	if err != nil {
		utils.PrintError("failed to delete Azure AD application: %v", err)
	} else {
		utils.PrintDefault("Azure AD application deleted successfully")
	}

	// Clean up local certificate files
	privateKeyPath := fmt.Sprintf("%s.key", clientID)
	certificatePath := fmt.Sprintf("%s.crt", clientID)

	// Remove private key file
	if err := os.Remove(privateKeyPath); err != nil {
		if !os.IsNotExist(err) {
			utils.PrintWarning("Warning: Could not remove private key file %s: %v", privateKeyPath, err)
		}
	} else {
		utils.PrintDefault("Removed local certificate file: %s", privateKeyPath)
	}

	// Remove certificate file
	if err := os.Remove(certificatePath); err != nil {
		if !os.IsNotExist(err) {
			utils.PrintWarning("Warning: Could not remove certificate file %s: %v", certificatePath, err)
		}
	} else {
		utils.PrintDefault("Removed local certificate file: %s", certificatePath)
	}

	utils.PrintDefault("Service principal and application deleted successfully: %s", clientID)
}

// removeRoleAssignments removes all role assignments for a service principal
func removeRoleAssignments(servicePrincipalID, subscriptionID string) error {
	if subscriptionID == "" {
		return fmt.Errorf("subscription ID is required for role assignment operations")
	}

	utils.PrintDefault("Removing role assignments for service principal %s in subscription %s", servicePrincipalID, subscriptionID)

	// List all role assignments for the subscription with filter by principal ID
	filter := fmt.Sprintf("principalId eq '%s'", servicePrincipalID)
	pager := azure.GetAuthClient().NewListPager(&armauthorization.RoleAssignmentsClientListOptions{Filter: &filter})

	var roleAssignmentsToDelete []struct {
		Name  string
		Scope string
	}

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return fmt.Errorf("failed to list role assignments: %v", err)
		}

		for _, assignment := range page.Value {
			if assignment.Properties != nil &&
				assignment.Properties.PrincipalID != nil &&
				*assignment.Properties.PrincipalID == servicePrincipalID {
				if assignment.Name != nil && assignment.Properties.Scope != nil {
					roleAssignmentsToDelete = append(roleAssignmentsToDelete, struct {
						Name  string
						Scope string
					}{
						Name:  *assignment.Name,
						Scope: *assignment.Properties.Scope,
					})
					utils.PrintDefault("Found role assignment to remove: %s at scope: %s", *assignment.Name, *assignment.Properties.Scope)
				}
			}
		}
	}

	// Delete each role assignment using the correct scope
	for _, assignment := range roleAssignmentsToDelete {
		_, err := azure.GetAuthClient().Delete(context.Background(), assignment.Scope, assignment.Name, nil)
		if err != nil {
			utils.PrintWarning("Failed to delete role assignment %s at scope %s: %v", assignment.Name, assignment.Scope, err)
		} else {
			utils.PrintDefault("Role assignment removed: %s at scope: %s", assignment.Name, assignment.Scope)
		}
	}

	return nil
}
