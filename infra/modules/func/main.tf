locals {
  localTags = merge(var.tags, {
    // Add additional key value pairs here if you want
  })
}

resource "azurerm_service_plan" "func-sp" {
  name                = "${var.tags.Project}-${var.env}"
  resource_group_name = var.rg.name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "FC1"
  tags                = local.localTags
}

resource "azurerm_storage_account" "func-sa" {
  #name                     = "vtnfuncappsa${var.env}"
  name                      = "${var.tags.Project}${var.env}"
  resource_group_name       = var.rg.name
  location                  = var.location
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  shared_access_key_enabled = true
  tags                      = local.localTags
}

resource "azurerm_storage_container" "flexcontainer" {
  name                  = "flexcontainer"
  storage_account_id    = azurerm_storage_account.func-sa.id
  container_access_type = "private"
}

# NOTE #
# consumption plan doesn't support managed identity access to the azure storage account it requires
resource "azurerm_function_app_flex_consumption" "func-app" {
  name                        = "${var.tags.Project}-${var.env}"
  resource_group_name         = var.rg.name
  location                    = var.location
  storage_container_type      = "blobContainer"
  storage_access_key          = azurerm_storage_account.func-sa.primary_access_key
  storage_authentication_type = "StorageAccountConnectionString"
  #storage_authentication_type   = "SystemAssignedIdentity"
  storage_container_endpoint    = "${azurerm_storage_account.func-sa.primary_blob_endpoint}${azurerm_storage_container.flexcontainer.name}"
  service_plan_id               = azurerm_service_plan.func-sp.id
  public_network_access_enabled = true
  tags                          = local.localTags
  runtime_name                  = "python"
  runtime_version               = "3.10"

  site_config {
    #    application_insights_key               = azurerm_application_insights.api_insights.instrumentation_key
    #    application_insights_connection_string = azurerm_application_insights.api_insights.connection_string

    cors {
      allowed_origins = ["https://"]
    }
  }


  identity {
    type = "SystemAssigned"
  }

  app_settings = {
    #"WEBSITE_AUTH_AAD_ALLOWED_TENANTS" = var.tenant_id
    #"WEBSITE_WEBDEPLOY_USE_SCM"        = true
    #"PYTHON_ENABLE_INIT_INDEXING" = "1"
    #"WEBSITE_RUN_FROM_PACKAGE" = 1
    #    "SCM_DO_BUILD_DURING_DEPLOYMENT"        = true
    #    "ENABLE_ORYX_BUILD"                     = true

    # >>>
    # https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference?tabs=blob&pivots=programming-language-python#connecting-to-host-storage-with-an-identity
    #"AzureWebJobsStorage__accountName"      = azurerm_storage_account.func-sa.name
    #"AzureWebJobsStorage" = ""
    #"AzureWebJobsStorage__credential"       = "managedidentity"
    #    "AzureWebJobsStorage__blobServiceUri" = "https://${azurerm_storage_account.func-sa.name}.blob.core.windows.net"
    #    "AzureWebJobsStorage__queueServiceUri" = "https://${azurerm_storage_account.func-sa.name}.queue.core.windows.net"
    #    "AzureWebJobsStorage__tableServiceUri" = "https://${azurerm_storage_account.func-sa.name}.table.core.windows.net"
    # >>>

  }
}
