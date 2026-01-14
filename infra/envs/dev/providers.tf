provider "azurerm" {
  subscription_id     = var.research_dev_subscription_id
  storage_use_azuread = true

  features {

  }
}
