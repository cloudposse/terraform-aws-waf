locals {
  regex_pattern_sets = local.enabled && var.regex_pattern_set_reference_statement_rules != null ? {
    for indx, rule in flatten(var.regex_pattern_set_reference_statement_rules) :
    lookup(rule, "name", null) != null ? format("%s-regex-pattern-set", rule.name) : format("regex-pattern-set-%d", rule.priority)
    => rule.statement.regex_pattern_set if try(rule.statement.regex_pattern_set, null) != null && try(rule.statement.arn, null) == null
  } : {}

  reusable_regex_pattern_sets = local.enabled && var.reusable_regex_pattern_sets != null ? {
    for indx, set in flatten(var.reusable_regex_pattern_sets) :
    format("%s-regex-pattern-set", set.name)
    => set.regex_pattern_set if try(set.regex_pattern_set, null) != null
  } : {}

  regex_rule_to_regex_pattern_set = local.enabled && local.regex_pattern_set_reference_statement_rules != null ? {
    for name, rule in local.regex_pattern_set_reference_statement_rules :
    name => lookup(rule, "name", null) != null ? format("%s-regex-pattern-set", rule.name) : format("regex-pattern-set-%d", rule.priority)
  } : {}

  regex_rule_to_reusable_regex_pattern_set = local.enabled && var.reusable_regex_pattern_sets != null ? {
    for indx, set in flatten(var.reusable_regex_pattern_sets) :
    set.name
    => format("%s-regex-pattern-set", set.name)
  } : {}
}

module "regex_pattern_set_label" {
  for_each = merge(local.regex_pattern_sets, local.reusable_regex_pattern_sets)

  source  = "cloudposse/label/null"
  version = "0.25.0"

  attributes = [each.key]
  context    = module.this.context
}

resource "aws_wafv2_regex_pattern_set" "default" {
  for_each = merge(local.regex_pattern_sets, local.reusable_regex_pattern_sets)

  name        = module.regex_pattern_set_label[each.key].id
  description = lookup(each.value, "description", null)
  scope       = var.scope

  dynamic "regular_expression" {
    for_each = each.value.regexes
    content {
      regex_string = regular_expression.value
    }
  }

  tags = module.this.tags
}
