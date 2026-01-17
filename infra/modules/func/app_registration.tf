locals {
  func_app_default_hostname = "${var.tags.Project}-${var.env}.azurewebsites.net"
}

resource "azuread_application_registration" "app" {
  display_name                           = "OIDC Toy"
  description                            = "A toy project demonstrating OIDC and Oauth2.0 authn/authz"
  sign_in_audience                       = "AzureADMyOrg"
  implicit_id_token_issuance_enabled     = true
  implicit_access_token_issuance_enabled = true
  homepage_url                           = "https://${local.func_app_default_hostname}/api/home"
  #logout_url            = "https://app.example.com/logout"
  #marketing_url         = "https://example.com/"
  #privacy_statement_url = "https://example.com/privacy"
  #support_url           = "https://support.example.com/"
  #terms_of_service_url  = "https://example.com/terms"
}

resource "azuread_application_redirect_uris" "redirect" {
  application_id = azuread_application_registration.app.id
  type           = "Web"

  redirect_uris = [
    "https://${local.func_app_default_hostname}/api/auth-response",
    "http://localhost:7071/api/auth-response"
  ]
}

resource "random_uuid" "example_administrator" {}

# Can create a basic Admin role for our app
resource "azuread_application_app_role" "example_administer" {
  application_id = azuread_application_registration.app.id
  role_id        = random_uuid.example_administrator.id

  allowed_member_types = ["User"]
  description          = "Admin roles have the ability to view all sessions and other data"
  display_name         = "Administer"
  value                = "admin"
}

data "azuread_client_config" "current" {
}

# 3. Create the Service Principal (The missing link)
resource "azuread_service_principal" "app_sp" {
  client_id = azuread_application_registration.app.client_id
}

resource "azuread_app_role_assignment" "current_admin" {
  app_role_id         = azuread_application_app_role.example_administer.role_id
  principal_object_id = data.azuread_client_config.current.object_id
  resource_object_id  = azuread_service_principal.app_sp.object_id
}

resource "azuread_application_password" "pw" {
  application_id = azuread_application_registration.app.id
}

output "client_secret" {
  value = azuread_application_password.pw.value
}

output "client_id" {
  value = azuread_application_registration.app.client_id
}
