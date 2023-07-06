locals {
  byte_match_statement_rules = local.enabled && var.byte_match_statement_rules != null ? {
    for rule in flatten(var.byte_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-byte-match-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}

  geo_allowlist_statement_rules = local.enabled && var.geo_allowlist_statement_rules != null ? {
    for rule in flatten(var.geo_allowlist_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-geo-allowlist-%d", module.this.id, rule.priority),
      "block",
    ) => rule
  } : {}

  geo_match_statement_rules = local.enabled && var.geo_match_statement_rules != null ? {
    for rule in flatten(var.geo_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-geo-match-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}

  ip_set_reference_statement_rules = local.enabled && var.ip_set_reference_statement_rules != null ? {
    for indx, rule in flatten(var.ip_set_reference_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-ip-set-reference-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}

  managed_rule_group_statement_rules = local.enabled && var.managed_rule_group_statement_rules != null ? {
    for rule in flatten(var.managed_rule_group_statement_rules) :
    lookup(rule, "name", null) != null ? rule.name : format("%s-managed-rule-group-%d", module.this.id, rule.priority) => rule
  } : {}

  rate_based_statement_rules = local.enabled && var.rate_based_statement_rules != null ? {
    for rule in flatten(var.rate_based_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-rate-based-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}

  rule_group_reference_statement_rules = local.enabled && var.rule_group_reference_statement_rules != null ? {
    for rule in flatten(var.rule_group_reference_statement_rules) :
    lookup(rule, "name", null) != null ? rule.name : format("%s-rule-group-reference-%d", module.this.id, rule.priority) => rule
  } : {}

  regex_pattern_set_reference_statement_rules = local.enabled && var.regex_pattern_set_reference_statement_rules != null ? {
    for rule in flatten(var.regex_pattern_set_reference_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-regex-pattern-set-reference-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}

  regex_match_statement_rules = local.enabled && var.regex_match_statement_rules != null ? {
    for rule in flatten(var.regex_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-regex-match-statement-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}

  size_constraint_statement_rules = local.enabled && var.size_constraint_statement_rules != null ? {
    for rule in flatten(var.size_constraint_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-size-constraint-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}

  sqli_match_statement_rules = local.enabled && var.sqli_match_statement_rules != null ? {
    for rule in flatten(var.sqli_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-sqli-match-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}

  xss_match_statement_rules = local.enabled && var.xss_match_statement_rules != null ? {
    for rule in flatten(var.xss_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-xss-match-%d", module.this.id, rule.priority),
      rule.action,
    ) => rule
  } : {}
}

resource "aws_wafv2_web_acl" "default" {
  count = local.enabled ? 1 : 0

  name        = module.this.id
  description = var.description
  scope       = var.scope
  tags        = module.this.tags

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [1] : []
      content {}
    }

    dynamic "block" {
      for_each = var.default_action == "block" ? [1] : []
      content {}
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = lookup(var.visibility_config, "cloudwatch_metrics_enabled", true)
    metric_name                = lookup(var.visibility_config, "metric_name", module.this.id)
    sampled_requests_enabled   = lookup(var.visibility_config, "sampled_requests_enabled", true)
  }

  dynamic "rule" {
    for_each = local.byte_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []

          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []

          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []

          content {}
        }
      }

      statement {
        dynamic "byte_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            positional_constraint = byte_match_statement.value.positional_constraint
            search_string         = byte_match_statement.value.search_string

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []

                  content {}
                }

                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []

                  content {}
                }

                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []

                  content {}
                }

                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []

                  content {}
                }

                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []

                  content {
                    name = single_header.value.name
                  }
                }

                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []

                  content {
                    name = single_query_argument.value.name
                  }
                }

                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []

                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? [
                for rule in lookup(rule.value.statement, "text_transformation") : {
                  priority = rule.priority
                  type     = rule.type
              }] : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.geo_allowlist_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        block {}
      }

      # `geo_allowlist_statement_rules` is a special case where we use `not_statement` to wrap our `statement` block to support
      # an "allowlist". Otherwise, using `geo_match_statement_rules` requires specifying ALL country codes that you
      # would like to blocklist.
      statement {
        not_statement {
          statement {
            dynamic "geo_match_statement" {
              for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

              content {
                country_codes = geo_match_statement.value.country_codes

                dynamic "forwarded_ip_config" {
                  for_each = lookup(geo_match_statement.value, "forwarded_ip_config", null) != null ? [geo_match_statement.value.forwarded_ip_config] : []

                  content {
                    fallback_behavior = forwarded_ip_config.value.fallback_behavior
                    header_name       = forwarded_ip_config.value.header_name
                  }
                }
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.geo_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "geo_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            country_codes = geo_match_statement.value.country_codes

            dynamic "forwarded_ip_config" {
              for_each = lookup(geo_match_statement.value, "forwarded_ip_config", null) != null ? [geo_match_statement.value.forwarded_ip_config] : []

              content {
                fallback_behavior = forwarded_ip_config.value.fallback_behavior
                header_name       = forwarded_ip_config.value.header_name
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.ip_set_reference_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "ip_set_reference_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            arn = ip_set_reference_statement.value.arn

            dynamic "ip_set_forwarded_ip_config" {
              for_each = lookup(ip_set_reference_statement.value, "ip_set_forwarded_ip_config", null) != null ? [ip_set_reference_statement.value.ip_set_forwarded_ip_config] : []

              content {
                fallback_behavior = ip_set_forwarded_ip_config.value.fallback_behavior
                header_name       = ip_set_forwarded_ip_config.value.header_name
                position          = ip_set_forwarded_ip_config.value.position
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.managed_rule_group_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = lookup(rule.value, "override_action", null) == "count" ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = lookup(rule.value, "override_action", null) != "count" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "managed_rule_group_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            name        = managed_rule_group_statement.value.name
            vendor_name = managed_rule_group_statement.value.vendor_name
            version     = lookup(managed_rule_group_statement.value, "version", null)

            dynamic "rule_action_override" {
              for_each = lookup(managed_rule_group_statement.value, "rule_action_override", null) != null ? managed_rule_group_statement.value.rule_action_override : {}

              content {
                name = rule_action_override.key

                action_to_use {
                  dynamic "allow" {
                    for_each = rule_action_override.value.action == "allow" ? [1] : []
                    content {}
                  }
                  dynamic "block" {
                    for_each = rule_action_override.value.action == "block" ? [1] : []
                    content {}
                  }
                  dynamic "count" {
                    for_each = rule_action_override.value.action == "count" ? [1] : []
                    content {}
                  }
                  dynamic "captcha" {
                    for_each = rule_action_override.value.action == "captcha" ? [1] : []
                    content {}
                  }
                }
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.rate_based_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "rate_based_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            aggregate_key_type = lookup(rate_based_statement.value, "aggregate_key_type", "IP")
            limit              = rate_based_statement.value.limit

            dynamic "forwarded_ip_config" {
              for_each = lookup(rate_based_statement.value, "forwarded_ip_config", null) != null ? [rate_based_statement.value.forwarded_ip_config] : []

              content {
                fallback_behavior = forwarded_ip_config.value.fallback_behavior
                header_name       = forwarded_ip_config.value.header_name
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.regex_pattern_set_reference_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "regex_pattern_set_reference_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            arn = regex_pattern_set_reference_statement.value.arn

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []

                  content {}
                }

                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []

                  content {}
                }

                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []

                  content {}
                }

                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []

                  content {}
                }

                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []

                  content {
                    name = single_header.value.name
                  }
                }

                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []

                  content {
                    name = single_query_argument.value.name
                  }
                }

                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []

                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? [
                for rule in lookup(rule.value.statement, "text_transformation") : {
                  priority = rule.priority
                  type     = rule.type
              }] : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.regex_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "regex_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            regex_string = regex_match_statement.value.regex_string

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []

                  content {}
                }

                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []

                  content {}
                }

                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []

                  content {}
                }

                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []

                  content {}
                }

                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []

                  content {
                    name = single_header.value.name
                  }
                }

                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []

                  content {
                    name = single_query_argument.value.name
                  }
                }

                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []

                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? [
                for rule in lookup(rule.value.statement, "text_transformation") : {
                  priority = rule.priority
                  type     = rule.type
              }] : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.rule_group_reference_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = lookup(rule.value, "override_action", null) == "count" ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = lookup(rule.value, "override_action", null) != "count" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "rule_group_reference_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            arn = rule_group_reference_statement.value.arn

            dynamic "rule_action_override" {
              for_each = lookup(rule_group_reference_statement.value, "rule_action_override", null) != null ? rule_group_reference_statement.value.rule_action_override : {}

              content {
                name = rule_action_override.key

                action_to_use {
                  dynamic "allow" {
                    for_each = rule_action_override.value.action == "allow" ? [1] : []
                    content {}
                  }
                  dynamic "block" {
                    for_each = rule_action_override.value.action == "block" ? [1] : []
                    content {}
                  }
                  dynamic "count" {
                    for_each = rule_action_override.value.action == "count" ? [1] : []
                    content {}
                  }
                  dynamic "captcha" {
                    for_each = rule_action_override.value.action == "captcha" ? [1] : []
                    content {}
                  }
                }
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.size_constraint_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }
      statement {
        dynamic "size_constraint_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {
            comparison_operator = size_constraint_statement.value.comparison_operator
            size                = size_constraint_statement.value.size

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []

                  content {}
                }

                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []

                  content {
                    # Oversize handling tells AWS WAF what to do with a web request when the request component that the rule inspects is over the limits.
                    # WAF does not support inspecting the entire contents of the body of a web request when the body exceeds 8 KB (8192 bytes).
                    # Only the first 8 KB of the request body are forwarded to WAF by the underlying host service
                    # Valid values include the following: CONTINUE, MATCH, NO_MATCH
                    oversize_handling = try(field_to_match.value.body.oversize_handling, "CONTINUE")
                  }
                }

                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []

                  content {}
                }

                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []

                  content {}
                }

                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []

                  content {
                    name = single_header.value.name
                  }
                }

                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []

                  content {
                    name = single_query_argument.value.name
                  }
                }

                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []

                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? [
                for rule in lookup(rule.value.statement, "text_transformation") : {
                  priority = rule.priority
                  type     = rule.type
              }] : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.sqli_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        dynamic "sqli_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []

                  content {}
                }

                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []

                  content {}
                }

                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []

                  content {}
                }

                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []

                  content {}
                }

                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []

                  content {
                    name = single_header.value.name
                  }
                }

                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []

                  content {
                    name = single_query_argument.value.name
                  }
                }

                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []

                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? [
                for rule in lookup(rule.value.statement, "text_transformation") : {
                  priority = rule.priority
                  type     = rule.type
              }] : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.xss_match_statement_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }
      statement {
        dynamic "xss_match_statement" {
          for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

          content {

            dynamic "field_to_match" {
              for_each = lookup(rule.value.statement, "field_to_match", null) != null ? [rule.value.statement.field_to_match] : []

              content {
                dynamic "all_query_arguments" {
                  for_each = lookup(field_to_match.value, "all_query_arguments", null) != null ? [1] : []

                  content {}
                }

                dynamic "body" {
                  for_each = lookup(field_to_match.value, "body", null) != null ? [1] : []

                  content {}
                }

                dynamic "method" {
                  for_each = lookup(field_to_match.value, "method", null) != null ? [1] : []

                  content {}
                }

                dynamic "query_string" {
                  for_each = lookup(field_to_match.value, "query_string", null) != null ? [1] : []

                  content {}
                }

                dynamic "single_header" {
                  for_each = lookup(field_to_match.value, "single_header", null) != null ? [field_to_match.value.single_header] : []

                  content {
                    name = single_header.value.name
                  }
                }

                dynamic "single_query_argument" {
                  for_each = lookup(field_to_match.value, "single_query_argument", null) != null ? [field_to_match.value.single_query_argument] : []

                  content {
                    name = single_query_argument.value.name
                  }
                }

                dynamic "uri_path" {
                  for_each = lookup(field_to_match.value, "uri_path", null) != null ? [1] : []

                  content {}
                }
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? [
                for rule in lookup(rule.value.statement, "text_transformation") : {
                  priority = rule.priority
                  type     = rule.type
              }] : []

              content {
                priority = text_transformation.value.priority
                type     = text_transformation.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [rule.value.visibility_config] : []

        content {
          cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
          metric_name                = visibility_config.value.metric_name
          sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
        }
      }
    }
  }

  dynamic "custom_response_body" {
    for_each = var.custom_response_body
    content {
      content      = custom_response_body.key["content"]
      content_type = custom_response_body.key["content_type"]
      key          = custom_response_body.key["key"]
    }
  }
}
