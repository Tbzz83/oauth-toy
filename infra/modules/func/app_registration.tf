resource "azuread_application_registration" "app" {
  display_name     = "OIDC Toy"
  description      = "A toy project demonstrating OIDC and Oauth2.0 authn/authz"
  sign_in_audience = "AzureADMyOrg"

  homepage_url          = "https://${azurerm_function_app_flex_consumption.func-app.default_hostname}/api/home"
  #logout_url            = "https://app.example.com/logout"
  #marketing_url         = "https://example.com/"
  #privacy_statement_url = "https://example.com/privacy"
  #support_url           = "https://support.example.com/"
  #terms_of_service_url  = "https://example.com/terms"
}
