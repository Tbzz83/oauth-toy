variable "research_dev_subscription_id" {
  sensitive = true
}

locals {
  env      = "dev"
  location = "eastus2"
  tags = {
    "Project"     = "oidctoy",
    "Environment" = local.env,
  }
}
