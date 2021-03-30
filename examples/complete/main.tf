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
      # statement = [
      #   {
      #     country_codes = ["NL"]
      #   },
      #   {
      #     country_codes = ["GB"]
      #   }
      # ]
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
      # statement = [
      #   {
      #     country_codes = ["NL"]
      #   },
      # ]
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

  context = module.this.context
}
