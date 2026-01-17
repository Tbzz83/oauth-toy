# TODO
# Current I don't have the right permissions to do
# `azuread_app_role_assignment` so I'll have to request that be 
# granted

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

resource "azuread_service_principal" "app_sp" {
  client_id = azuread_application_registration.app.client_id
}

# resource "azuread_app_role_assignment" "current_admin" {
#   app_role_id         = azuread_application_app_role.example_administer.role_id
#   principal_object_id = data.azuread_client_config.current.object_id
#   resource_object_id  = azuread_service_principal.app_sp.object_id
# }
