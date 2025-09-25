# Assign roles to the provisioner identity
data "azurerm_resource_group" "zones" {
  name = var.zones_rg_name
}

data "azurerm_key_vault" "kv" {
  name                = replace(replace(var.key_vault_url, "https://", ""), ".vault.azure.net/", "")
  resource_group_name = data.azurerm_resource_group.zones.name
}

# DNS Zone Contributor role assignment
resource "azurerm_role_assignment" "zones_rg" {
  scope                = data.azurerm_resource_group.zones.id
  role_definition_name = "DNS Zone Contributor"
  principal_id         = azurerm_user_assigned_identity.provisioner_identity.principal_id
}

# Key Vault Certificates Officer role assignment
resource "azurerm_role_assignment" "kv" {
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = azurerm_user_assigned_identity.provisioner_identity.principal_id
}
