provider "aws" {
  region = var.region
}

module "waf" {
  source = "../.."

  visibility_config = {
    cloudwatch_metrics_enabled = false
    metric_name                = "rules-example-metric"
    sampled_requests_enabled   = false
  }

  # Custom response bodies for rate limiting
  custom_response_body = {
    rate_limit_exceeded = {
      content      = "{\"error\": \"Rate limit exceeded\", \"message\": \"Too many requests. Please try again later.\", \"retry_after\": 300}"
      content_type = "APPLICATION_JSON"
    }
  }

  # https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
  managed_rule_group_statement_rules = [
    {
      name     = "AWS-AWSManagedRulesAdminProtectionRuleSet"
      priority = 1

      statement = {
        name        = "AWSManagedRulesAdminProtectionRuleSet"
        vendor_name = "AWS"
        scope_down_statement = {
          byte_match_statement = {
            positional_constraint = "STARTS_WITH"
            search_string         = "example-scope-down-statement"
            field_to_match = {
              uri_path = true
            }
            text_transformation = [
              {
                priority = 40
                type     = "NONE"
              }
            ]
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesAdminProtectionRuleSet"
      }
    },
    {
      name     = "AWS-AWSManagedRulesAmazonIpReputationList"
      priority = 2

      statement = {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesAmazonIpReputationList"
      }
    },
    {
      name     = "AWS-AWSManagedRulesCommonRuleSet"
      priority = 3

      statement = {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesCommonRuleSet"
      }
    },
    {
      name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
      priority = 4

      statement = {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
      }
    },
    # https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html
    {
      name     = "AWS-AWSManagedRulesBotControlRuleSet"
      priority = 5

      statement = {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"

        rule_action_override = {
          CategoryHttpLibrary = {
            action = "block"
            custom_response = {
              response_code = "404"
              response_header = {
                name  = "example-1"
                value = "example-1"
              }
            }
          }
          SignalNonBrowserUserAgent = {
            action = "count"
            custom_request_handling = {
              insert_header = {
                name  = "example-2"
                value = "example-2"
              }
            }
          }
        }

        managed_rule_group_configs = [
          {
            aws_managed_rules_bot_control_rule_set = {
              inspection_level = "COMMON"
            }
          }
        ]
      }

      scope_down_not_statement_enabled = true
      scope_down_statement = {
        byte_match_statement = {
          field_to_match = {
            single_header = {
              name = "x-bypass-token"
            }
          }
          positional_constraint = "EXACTLY"
          search_string         = "TEST_TOKEN"
          text_transformation = [
            {
              priority = 20
              type     = "NONE"
            }
          ]
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesBotControlRuleSet"
      }
    },
    {
      name     = "AWS-AWSManagedRulesAntiDDoSRuleSet"
      priority = 6

      statement = {
        name        = "AWSManagedRulesAntiDDoSRuleSet"
        vendor_name = "AWS"

        managed_rule_group_configs = [
          {
            aws_managed_rules_anti_ddos_rule_set = {
              sensitivity_to_block = "LOW"
              client_side_action_config = {
                challenge = {
                  usage_of_action = "ENABLED"
                  sensitivity     = "LOW"
                  exempt_uri_regular_expression = [
                    {
                      regex_string = "/api/|\\.(acc|avi|css|gif|jpe?g|js|mp[34]|ogg|otf|pdf|png|tiff?|ttf|webm|webp|woff2?)$"
                    }
                  ]
                }
              }
            }
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesAntiDDoSRuleSet"
      }
    },
    {
      name     = "AWS-AWSManagedRulesACFPRuleSet"
      priority = 7

      statement = {
        name        = "AWSManagedRulesACFPRuleSet"
        vendor_name = "AWS"
        managed_rule_group_configs = [
          {
            aws_managed_rules_acfp_rule_set = {
              creation_path          = "/web/newaccount"
              registration_page_path = "/web/registerhere"
              request_inspection = {
                payload_type = "FORM_ENCODED"
                password_field = {
                  identifier = "password"
                }
                username_field = {
                  identifier = "username1"
                }
                email_field = {
                  identifier = "email"
                }
                address_fields = {
                  identifiers = ["primaryaddressline1", "primaryaddressline2"]
                }
                phone_number_fields = {
                  identifiers = ["cellphone", "homephone"]
                }
              }
              # Note that Response Inspection is available only on web ACLs that protect CloudFront distributions.
              # response_inspection = {
              #   #you can only have one entry here. Cannot have multiple of header, json, status_code
              #   json = {
              #     identifier      = "/login/success"
              #     success_values = ["True", "Succeeded"]
              #     failure_values = ["Failure JSON"]
              #   }
              # }
            }
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesACFPRuleSet"
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

  # Example from https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control-example-user-agent-exception.html
  custom_rules = [
    {
      name     = "user_agent_match_rule"
      priority = 1000
      action   = "block"

      and_statement = [
        {
          type = "LabelMatchStatement"
          statement = {
            key   = "awswaf:managed:aws:bot-control:signal:non-browser-user-agent"
            scope = "LABEL"
          }
        },
        {
          type = "NotStatement"
          statement = {
            type = "ByteMatchStatement"
            field_to_match = {
              single_header = {
                name = "user-agent"
              }
            }
            positional_constraint = "EXACTLY"
            search_string         = "PostmanRuntime/7.29.2"
            text_transformation = [
              {
                priority = 0
                type     = "NONE"
              }
            ]
          }
        }
      ]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "user_agent_match_rule"
      }
    }
  ]

  rate_based_statement_rules = [
    {
      name     = "rule-40"
      action   = "block"
      priority = 40

      # Custom response for rate limiting with HTTP 429 status
      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header = {
          name  = "Retry-After"
          value = "300"
        }
      }

      statement = {
        limit                 = 100
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300
        scope_down_statement = {
          byte_match_statement = {
            positional_constraint = "STARTS_WITH"
            search_string         = "example-scope-down-statement"
            field_to_match = {
              uri_path = true
            }
            text_transformation = [
              {
                priority = 40
                type     = "NONE"
              }
            ]
          }
        }
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

  geo_match_statement_rules = [
    {
      name     = "rule-80"
      action   = "count"
      priority = 80

      statement = {
        country_codes = ["NL", "GB"]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-80-metric"
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
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-11-metric"
      }
    }
  ]

  geo_allowlist_statement_rules = [
    {
      name     = "rule-90"
      priority = 90
      action   = "count"

      statement = {
        country_codes = ["US"]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-90-metric"
      }
    },
    {
      name     = "rule-95"
      priority = 95
      action   = "block"

      statement = {
        country_codes = ["US"]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-95-metric"
      }
    }
  ]

  regex_match_statement_rules = [
    {
      name     = "rule-100"
      priority = 100
      action   = "block"

      statement = {
        regex_string = "^/admin"

        text_transformation = [
          {
            priority = 90
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
        metric_name                = "rule-100-metric"
      }
    }
  ]

  ip_set_reference_statement_rules = [
    {
      name     = "rule-110"
      priority = 110
      action   = "block"

      statement = {
        ip_set = {
          ip_address_version = "IPV4"
          addresses          = ["17.0.0.0/8"]
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-110-metric"
      }
    }
  ]

  nested_statement_rules = [
    {
      name     = "rule-120"
      priority = 120
      action   = "block"

      statement = {
        and_statement = {
          statements = [
            {
              type = "label_match_statement"
              statement = jsonencode({
                scope = "LABEL"
                key   = "internal"
              })
            },
            {
              type = "not_byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "/authorized"
                field_to_match = {
                  uri_path = {}
                }
                text_transformation = [{
                  priority = 1,
                  type     = "URL_DECODE"
                }]
              })
            },
            {
              type = "not_byte_match_statement"
              statement = jsonencode({
                positional_constraint = "CONTAINS"
                search_string         = "AuthorizedBot"
                field_to_match = {
                  single_header = {
                    name = "user-agent"
                  }
                }
                text_transformation = [{
                  priority = 1,
                  type     = "LOWERCASE"
                }]
              })
            }
          ]
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "rule-120-metric"
      }
    }
  ]

  context = module.this.context
}
