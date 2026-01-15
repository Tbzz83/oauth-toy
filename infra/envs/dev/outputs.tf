output "client_secret" {
  value     = module.func.client_secret
  sensitive = true
}

output "client_id" {
  value     = module.func.client_id
  sensitive = true
}
