module "func" {
  source = "../../modules/func"
  rg = module.rg.rg
  location = local.location
  tags = local.tags
  env = local.env
}
