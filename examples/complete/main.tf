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

  context = module.this.context
}
