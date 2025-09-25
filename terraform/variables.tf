variable "subscription_id" {
  type = string
}

variable "group_name_prefix" {
  type = string
}

variable "project_name" {
  type = string
}

variable "location" {
  type    = string
  default = "polandcentral"
}

variable "law_sku" {
  type    = string
  default = "PerGB2018"
}

variable "image_name" {
  type = string
}

variable "zones_rg_name" {
  type = string
}

variable "key_vault_url" {
  type = string
}

variable "lego_email" {
  type = string
}
