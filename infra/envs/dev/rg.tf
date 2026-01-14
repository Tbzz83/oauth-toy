module "rg" {
  source   = "../../modules/rg"
  name     = "${local.tags.Project}-${local.env}"
  tags     = local.tags
  location = local.location
}
