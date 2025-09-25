terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.1.0"
    }
  }
}

provider "azurerm" {
  features {}

  storage_use_azuread = true
  subscription_id     = var.subscription_id
}

resource "random_string" "sa_suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  resource_group_name = "${var.group_name_prefix}-${var.project_name}"
  sa_name             = "${substr(replace(lower(var.project_name), "/[^a-z0-9]/", ""), 0, 18)}${random_string.sa_suffix.result}"
}

# Create a resource group for Container App resources
resource "azurerm_resource_group" "provisioner" {
  name     = local.resource_group_name
  location = var.location
}

# Azure Storage
resource "azurerm_storage_account" "provisioner" {
  name                      = local.sa_name
  location                  = azurerm_resource_group.provisioner.location
  resource_group_name       = azurerm_resource_group.provisioner.name
  account_kind              = "StorageV2"
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  shared_access_key_enabled = true
}

resource "azurerm_storage_share" "provisioner" {
  name               = "provisioner"
  storage_account_id = azurerm_storage_account.provisioner.id
  quota              = 10
  enabled_protocol   = "SMB"
}

resource "azurerm_log_analytics_workspace" "provisioner" {
  name                = "${var.project_name}-law"
  location            = azurerm_resource_group.provisioner.location
  resource_group_name = azurerm_resource_group.provisioner.name
  sku                 = var.law_sku
}

# Create a container app environment
resource "azurerm_container_app_environment" "provisioner" {
  name                = "${var.project_name}-env"
  location            = azurerm_resource_group.provisioner.location
  resource_group_name = azurerm_resource_group.provisioner.name
  logs_destination    = "azure-monitor"

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
}

resource "azurerm_container_app_environment_storage" "provioner_vol" {
  name                         = "provisioner"
  container_app_environment_id = azurerm_container_app_environment.provisioner.id
  share_name                   = "provisioner"
  access_mode                  = "ReadWrite"
  account_name                 = azurerm_storage_account.provisioner.name
  access_key                   = azurerm_storage_account.provisioner.primary_access_key
}

resource "azurerm_monitor_diagnostic_setting" "env_monitor_setting" {
  name                       = "SendAllToLAW"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.provisioner.id
  storage_account_id         = azurerm_storage_account.provisioner.id
  target_resource_id         = azurerm_container_app_environment.provisioner.id

  enabled_log {
    category_group = "allLogs"
  }
}

resource "azurerm_user_assigned_identity" "provisioner_identity" {
  name                = "${var.project_name}-identity"
  location            = azurerm_resource_group.provisioner.location
  resource_group_name = azurerm_resource_group.provisioner.name
}

# Assign AcrPull role to the registry
resource "azurerm_role_assignment" "provisioner_acr_pul" {
  scope              = "/subscriptions/c885a276-c882-483f-b216-42f73715161d/resourceGroups/dom-lab-common/providers/Microsoft.ContainerRegistry/registries/skdomlab"
  role_definition_id = "/subscriptions/c885a276-c882-483f-b216-42f73715161d/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d" # AcrPull
  principal_id       = azurerm_user_assigned_identity.provisioner_identity.principal_id
}

resource "azurerm_container_app_job" "provisioner" {
  name                         = "${var.project_name}-job"
  location                     = azurerm_resource_group.provisioner.location
  resource_group_name          = azurerm_resource_group.provisioner.name
  container_app_environment_id = azurerm_container_app_environment.provisioner.id
  replica_timeout_in_seconds   = 900
  workload_profile_name        = "Consumption"

  template {
    container {
      image  = var.image_name
      name   = var.project_name
      cpu    = 0.5
      memory = "1Gi"

      args = [
        "list"
      ]

      env {
        name  = "AZURE_SUBSCRIPTION_ID"
        value = var.subscription_id
      }

      env {
        name  = "AZURE_RESOURCE_GROUP"
        value = var.zones_rg_name
      }

      env {
        name  = "AZURE_KEY_VAULT_URL"
        value = var.key_vault_url
      }

      env {
        name  = "LEGO_EMAIL"
        value = var.lego_email
      }

      env {
        name  = "AZURE_AUTH_METHOD"
        value = "msi"
      }

      env {
        name  = "AZURE_TENANT_ID"
        value = "ce45d437-ed75-4a4f-9d57-87e1ef73f8d6"
      }

      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.provisioner_identity.client_id
      }
    }
  }

  manual_trigger_config {
    replica_completion_count = 1
    parallelism              = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.provisioner_identity.id]
  }

  registry {
    server   = "skdomlab.azurecr.io"
    identity = azurerm_user_assigned_identity.provisioner_identity.id
  }

  depends_on = [azurerm_role_assignment.provisioner_acr_pul]
}
