locals {
  func_app_default_hostname = "${var.tags.Project}-${var.env}.azurewebsites.net"
}

resource "azuread_application_registration" "app" {
  display_name                       = "OIDC Toy"
  description                        = "A toy project demonstrating OIDC and Oauth2.0 authn/authz"
  sign_in_audience                   = "AzureADMyOrg"
  implicit_id_token_issuance_enabled = true
  homepage_url                       = "https://${local.func_app_default_hostname}/api/home"
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

resource "azuread_application_password" "pw" {
  application_id = azuread_application_registration.app.id
}

output "client_secret" {
  value = azuread_application_password.pw.value
}

output "client_id" {
  value = azuread_application_registration.app.client_id
}
