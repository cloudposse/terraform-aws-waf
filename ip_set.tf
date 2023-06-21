resource "aws_wafv2_ip_set" "ip_set" {
  for_each = local.ip_set_allow_block_rules
  
  name               = each.value.name
  description        = each.value.description != null ? each.value.description : null
  scope              = var.scope
  ip_address_version = each.value.ip_address_version
  addresses          = each.value.addresses
  tags               = module.this.tags
}
