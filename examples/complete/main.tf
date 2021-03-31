provider "aws" {
  region = var.region
}

module "waf" {
  source = "../.."

  geo_match_statement_rules = [
    {
      name     = "rule-10"
      action   = "count"
      priority = 10

      statement = {
        country_codes = ["NL", "GB"]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = false
        metric_name                = "rule-10-metric"
      }
    },
    {
      name     = "rule-11"
      action   = "allow"
      priority = 11

      statement = {
        country_codes = ["US"]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = false
        metric_name                = "rule-11-metric"
      }
    }
  ]

  managed_rule_group_statement_rules = [
    {
      name            = "rule-20"
      override_action = "count"
      priority        = 20

      statement = {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        excluded_rule = [
          "SizeRestrictions_QUERYSTRING",
          "NoUserAgent_HEADER"
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-20-metric"
      }
    }
  ]

  byte_match_statement_rules = [
    {
      name     = "rule-30"
      action   = "allow"
      priority = 30

      statement = {
        positional_constraint = "EXACTLY"
        search_string         = "/cp-key"

        text_transformation = [
          {
            priority = 30
            type     = "COMPRESS_WHITE_SPACE"
          }
        ]

        field_to_match = {
          uri_path = {}
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-30-metric"
      }
    }
  ]

  rate_based_statement_rules = [
    {
      name     = "rule-40"
      action   = "block"
      priority = 40

      statement = {
        limit              = 100
        aggregate_key_type = "IP"
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-40-metric"
      }
    }
  ]

  size_constraint_statement_rules = [
    {
      name     = "rule-50"
      action   = "block"
      priority = 50

      statement = {
        comparison_operator = "GT"
        size                = 15

        field_to_match = {
          all_query_arguments = {}
        }

        text_transformation = [
          {
            type     = "COMPRESS_WHITE_SPACE"
            priority = 1
          }
        ]

      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-50-metric"
      }
    }
  ]

  xss_match_statement_rules = [
    {
      name     = "rule-60"
      action   = "block"
      priority = 60

      statement = {
        field_to_match = {
          uri_path = {}
        }

        text_transformation = [
          {
            type     = "URL_DECODE"
            priority = 1
          },
          {
            type     = "HTML_ENTITY_DECODE"
            priority = 2
          }
        ]

      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-60-metric"
      }
    }
  ]

  sqli_match_statement_rules = [
    {
      name     = "rule-70"
      action   = "block"
      priority = 70

      statement = {

        field_to_match = {
          query_string = {}
        }

        text_transformation = [
          {
            type     = "URL_DECODE"
            priority = 1
          },
          {
            type     = "HTML_ENTITY_DECODE"
            priority = 2
          }
        ]

      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-70-metric"
      }
    }
  ]

  context = module.this.context
}
