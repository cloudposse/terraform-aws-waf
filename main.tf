locals {
  waf_enabled = module.this.enabled && web_acl_rules != null ? true : false

  byte_match_statement_rules = module.this.enabled && var.byte_match_statement_rules != null ? {
    for indx, rule in flatten(var.byte_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  geo_match_statement_rules = module.this.enabled && var.geo_match_statement_rules != null ? {
    for indx, rule in flatten(var.geo_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  ip_set_reference_statement_rules = module.this.enabled && var.ip_set_reference_statement_rules != null ? {
    for indx, rule in flatten(var.ip_set_reference_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  managed_rule_group_statement_rules = module.this.enabled && var.managed_rule_group_statement_rules != null ? {
    for indx, rule in flatten(var.managed_rule_group_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  rate_based_statement_rules = module.this.enabled && var.rate_based_statement_rules != null ? {
    for indx, rule in flatten(var.rate_based_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  regex_pattern_set_reference_statement_ruless = module.this.enabled && var.regex_pattern_set_reference_statement_ruless != null ? {
    for indx, rule in flatten(var.regex_pattern_set_reference_statement_ruless) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  rule_group_reference_statement_rules = module.this.enabled && var.rule_group_reference_statement_rules != null ? {
    for indx, rule in flatten(var.rule_group_reference_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  regex_pattern_set_reference_statement_rules = module.this.enabled && var.regex_pattern_set_reference_statement_rules != null ? {
    for indx, rule in flatten(var.regex_pattern_set_reference_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  sqli_match_statement_rules = module.this.enabled && var.sqli_match_statement_rules != null ? {
    for indx, rule in flatten(var.sqli_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
  xss_match_statement_rules = module.this.enabled && var.xss_match_statement_rules != null ? {
    for indx, rule in flatten(var.xss_match_statement_rules) :
    format("%s-%s",
      lookup(rule, "name", null) != null ? rule.name : format("%s-%d", module.this.id, indx),
      rule.action,
    ) => rule
  } : {}
}

resource "aws_wafv2_web_acl" "default" {
  count = local.waf_enabled ? 1 : 0

  name        = module.this.id
  description = var.description
  scope       = var.scope

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

  dynamic "visibility_config" {
    for_each = var.visibility_config == null ? [] : [var.visibility_config]

    content {
      cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
      metric_name                = lookup(visibility_config.value, "metric_name", module.this.id)
      sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
    }
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
                all_query_arguments   = lookup(field_to_match.value.all_query_arguments, null)
                body                  = lookup(field_to_match.value.body, null)
                method                = lookup(field_to_match.value.method, null)
                query_string          = lookup(field_to_match.value.query_string, null)
                single_header         = lookup(field_to_match.value.single_header, null)
                single_query_argument = lookup(field_to_match.value.single_query_argument, null)
                uri_path              = lookup(field_to_match.value.uri_path, null)
              }
            }

            dynamic "text_transformation" {
              for_each = lookup(rule.value.statement, "text_transformation", null) != null ? [rule.value.statement.text_transformation] : []

              content {
                priority = field_to_match.value.priority
                type     = field_to_match.value.type
              }
            }
          }
        }
      }

      dynamic "visibility_config" {
        for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

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
      }
    }

    statement {
      dynamic "geo_match_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {
          country_codes = geo_match_statement.value.country_codes

          dynamic "forwarded_ip_config" {
            for_each = lookup(geo_match_statement.value, "forwarded_ip_config", null) != null ? [] : [geo_match_statement.value.forwarded_ip_config]

            content {
              fallback_behavior = forwarded_ip_config.value.fallback_behavior
              header_name       = forwarded_ip_config.value.header_name
            }
          }
        }
      }
    }

    dynamic "visibility_config" {
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
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
      }
    }

    statement {
      dynamic "ip_set_reference_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {
          arn = ip_set_reference_statement.value.arn

          dynamic "ip_set_forwarded_ip_config" {
            for_each = lookup(ip_set_reference_statement.value, "ip_set_forwarded_ip_config", null) != null ? [] : [ip_set_reference_statement.value.ip_set_forwarded_ip_config]

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
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
      }
    }
  }

  dynamic "rule" {
    for_each = local.managed_rule_group_statement_rules

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

      override_action {
        dynamic "none" {
          for_each = rule.value.override_action == "none" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
      }
    }

    statement {
      dynamic "managed_rule_group_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {
          name        = managed_rule_group_statement.value.name
          vendor_name = managed_rule_group_statement.value.vendor_name

          dynamic "excluded_rule" {
            for_each = lookup(managed_rule_group_statement.value, "excluded_rule", null) != null ? [] : [managed_rule_group_statement.value.excluded_rule]

            content {
              name = excluded_rule.value.name
            }
          }
        }
      }
    }

    dynamic "visibility_config" {
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
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
      }
    }

    statement {
      dynamic "rate_based_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {
          aggregate_key_type = lookup(rate_based_statement.value, "aggregate_key_type", "IP")
          limit              = rate_based_statement.value.limit

          dynamic "forwarded_ip_config" {
            for_each = lookup(rate_based_statement.value, "forwarded_ip_config", null) != null ? [] : [rate_based_statement.value.forwarded_ip_config]

            content {
              fallback_behavior = forwarded_ip_config.value.fallback_behavior
              header_name       = forwarded_ip_config.value.header_name
            }
          }
        }
      }
    }

    dynamic "visibility_config" {
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
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
    }

    statement {
      dynamic "regex_pattern_set_reference_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {
          arn = regex_pattern_set_reference_statement.value.arn

          dynamic "field_to_match" {
            for_each = lookup(regex_pattern_set_reference_statement.value, "field_to_match", null) != null ? [regex_pattern_set_reference_statement.value.field_to_match] : []

            content {
              all_query_arguments   = lookup(field_to_match.value.all_query_arguments, null)
              body                  = lookup(field_to_match.value.body, null)
              method                = lookup(field_to_match.value.method, null)
              query_string          = lookup(field_to_match.value.query_string, null)
              single_header         = lookup(field_to_match.value.single_header, null)
              single_query_argument = lookup(field_to_match.value.single_query_argument, null)
              uri_path              = lookup(field_to_match.value.uri_path, null)
            }
          }

          dynamic "text_transformation" {
            for_each = lookup(regex_pattern_set_reference_statement.value, "text_transformation", null) != null ? [regex_pattern_set_reference_statement.value.text_transformation] : []

            content {
              priority = field_to_match.value.priority
              type     = field_to_match.value.type
            }
          }
        }
      }
    }

    dynamic "visibility_config" {
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
      }
    }
  }

  dynamic "rule" {
    for_each = local.rule_group_reference_statement_rules

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

      override_action {
        dynamic "none" {
          for_each = rule.value.override_action == "none" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
      }
    }

    statement {
      dynamic "rule_group_reference_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {
          arn = rule_group_reference_statement.value.arn

          dynamic "excluded_rule" {
            for_each = lookup(rule_group_reference_statement.value, "excluded_rule", null) != null ? [] : [rule_group_reference_statement.value.excluded_rule]

            content {
              name = excluded_rule.value.name
            }
          }
        }
      }
    }

    dynamic "visibility_config" {
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
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
      }
    }

    statement {
      dynamic "size_constraint_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {
          comparison_operator = size_constraint_statement.value.comparison_operator
          size                = size_constraint_statement.value.size

          dynamic "field_to_match" {
            for_each = lookup(size_constraint_statement.value, "field_to_match", null) != null ? [size_constraint_statement.value.field_to_match] : []

            content {
              all_query_arguments   = lookup(field_to_match.value.all_query_arguments, null)
              body                  = lookup(field_to_match.value.body, null)
              method                = lookup(field_to_match.value.method, null)
              query_string          = lookup(field_to_match.value.query_string, null)
              single_header         = lookup(field_to_match.value.single_header, null)
              single_query_argument = lookup(field_to_match.value.single_query_argument, null)
              uri_path              = lookup(field_to_match.value.uri_path, null)
            }
          }

          dynamic "text_transformation" {
            for_each = lookup(size_constraint_statement.value, "text_transformation", null) != null ? [size_constraint_statement.value.text_transformation] : []

            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }

        }
      }
    }

    dynamic "visibility_config" {
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
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
      }
    }

    statement {
      dynamic "sqli_match_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {

          dynamic "field_to_match" {
            for_each = lookup(sqli_match_statement.value, "field_to_match", null) != null ? [sqli_match_statement.value.field_to_match] : []

            content {
              all_query_arguments   = lookup(field_to_match.value.all_query_arguments, null)
              body                  = lookup(field_to_match.value.body, null)
              method                = lookup(field_to_match.value.method, null)
              query_string          = lookup(field_to_match.value.query_string, null)
              single_header         = lookup(field_to_match.value.single_header, null)
              single_query_argument = lookup(field_to_match.value.single_query_argument, null)
              uri_path              = lookup(field_to_match.value.uri_path, null)
            }
          }

          dynamic "text_transformation" {
            for_each = lookup(sqli_match_statement.value, "text_transformation", null) != null ? [sqli_match_statement.value.text_transformation] : []

            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }

        }
      }
    }

    dynamic "visibility_config" {
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
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
      }
    }

    statement {
      dynamic "xss_match_statement" {
        for_each = lookup(rule.value, "statement", null) != null ? [rule.value.statement] : []

        content {

          dynamic "field_to_match" {
            for_each = lookup(xss_match_statement.value, "field_to_match", null) != null ? [xss_match_statement.value.field_to_match] : []

            content {
              all_query_arguments   = lookup(field_to_match.value.all_query_arguments, null)
              body                  = lookup(field_to_match.value.body, null)
              method                = lookup(field_to_match.value.method, null)
              query_string          = lookup(field_to_match.value.query_string, null)
              single_header         = lookup(field_to_match.value.single_header, null)
              single_query_argument = lookup(field_to_match.value.single_query_argument, null)
              uri_path              = lookup(field_to_match.value.uri_path, null)
            }
          }

          dynamic "text_transformation" {
            for_each = lookup(xss_match_statement.value, "text_transformation", null) != null ? [xss_match_statement.value.text_transformation] : []

            content {
              priority = text_transformation.value.priority
              type     = text_transformation.value.type
            }
          }

        }
      }
    }

    dynamic "visibility_config" {
      for_each = lookup(rule.value, "visibility_config", null) != null ? [var.visibility_config] : []

      content {
        cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics_enabled", true)
        metric_name                = visibility_config.value.metric_name
        sampled_requests_enabled   = lookup(visibility_config.value, "sampled_requests_enabled", true)
      }
    }
  }

  tags = module.this.tags
}

