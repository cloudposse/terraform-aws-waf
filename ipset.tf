locals {
  ip_sets = local.enabled && var.ip_set_reference_statement_rules != null ? {
    for indx, rule in flatten(var.ip_set_reference_statement_rules) :
    lookup(rule, "name", null) != null ? format("%s-ip-set", rule.name) : format("ip-set-%d", rule.priority)
    => rule.statement.ip_set if try(rule.statement.ip_set, null) != null && try(rule.statement.arn, null) == null
  } : {}

  reusable_ip_sets = local.enabled && var.reusable_ip_sets != null ? {
    for indx, set in flatten(var.reusable_ip_sets) :
    format("%s-ip-set", set.name)
    => set.ip_set if try(set.ip_set, null) != null
  } : {}

  ip_rule_to_ip_set = local.enabled && local.ip_set_reference_statement_rules != null ? {
    for name, rule in local.ip_set_reference_statement_rules :
    name => lookup(rule, "name", null) != null ? format("%s-ip-set", rule.name) : format("ip-set-%d", rule.priority)
  } : {}

  ip_rule_to_reusable_ip_set = local.enabled && var.reusable_ip_sets != null ? {
    for indx, set in flatten(var.reusable_ip_sets) :
    set.name
    => format("%s-ip-set", set.name)
  } : {}
}

module "ip_set_label" {
  for_each = merge(local.ip_sets, local.reusable_ip_sets)

  source  = "cloudposse/label/null"
  version = "0.25.0"

  attributes = [each.key]
  context    = module.this.context
}

resource "aws_wafv2_ip_set" "default" {
  for_each = merge(local.ip_sets, local.reusable_ip_sets)

  name               = module.ip_set_label[each.key].id
  description        = lookup(each.value, "description", null)
  scope              = var.scope
  ip_address_version = each.value.ip_address_version
  addresses          = each.value.addresses

  tags = module.this.tags
}
