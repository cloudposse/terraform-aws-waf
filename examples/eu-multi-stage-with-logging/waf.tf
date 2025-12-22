module "waf" {
  source = "../.."

  # Context
  enabled     = true
  environment = var.environment
  stage       = var.stage
  name        = var.name

  # WAF specific
  visibility_config = {
    cloudwatch_metrics_enabled = true
    sampled_requests_enabled   = true
    metric_name                = "${var.environment}-${var.stage}-${var.name}"
  }

  # not in WAF TEST RULE
  custom_response_body = {
    rate_limit_exceeded = {
      content      = "{\"error\": \"Rate limit exceeded\", \"message\": \"Too many requests. Please try again later.\", \"retry_after\": 300}"
      content_type = "APPLICATION_JSON"
    }
  }

  # Unset for automated testing
  # association_resource_arns = var.association_resource_arns
  default_action = "allow"
  description    = "This is a generic WebACL for ${var.environment}-${var.stage} ALBs"

  /* Logging Defintions */
  log_destination_configs = [module.cloudwatch_logs.log_group_arn]
  logging_filter = {
    default_behavior = "KEEP"

    /* Example Filter to redact from output if a count is triggered in a rulegroup
    filter = [{
      behavior = "DROP"
      condition = [{
        action_condition = {
          action = "COUNT"
        },
        label_name_condition = {
          label_name = "awswaf:111122223333:rulegroup:testRules:LabelNameZ"
        }]
      }
      requirement = "MEETS_ALL"
    }]
    */

    filter = [{
      behavior = "KEEP"
      condition = [
        {
          action_condition = {
            action = "BLOCK"
          }
        },
        {
          action_condition = {
            action = "COUNT"
          }
        }
      ]
      requirement = "MEETS_ANY"
    }]
  }

  # Remove fields from being logged in CloudWatch
  redacted_fields = {
    single_header = {
      name = "body"
    }
  }

  # IP Sets to generate without attachment to rulesets
  reusable_ip_sets = [
    { # TICKET-ID: Vulnerability scan event from single source in US on GCP Cloud
      name = "Custom-Event-TICKET-ID-VulnerabilityScan"
      ip_set = {
        description        = "Matches IP addresses used to scan REPLACE_WITH_URI for vulnerabilities"
        ip_address_version = "IPV4"
        addresses          = ["34.1.1.1/32"]
      }
    }
  ]

  # Regex Pattern Sets to generate without attachment to rulesets
  reusable_regex_pattern_sets = [
    { # Allows Let's Encrypt challenges to connect
      name = "Custom-UriPathAllowList"
      regex_pattern_set = {
        description = "Allowlist for URI Paths"
        regexes     = ["^(\\/\\.well-known\\/acme-challenge\\/.*)$"]
      }
    },
    { # TICKET-ID: Match trusted traffic based on JA4 for Qualys scans
      name = "Custom-JA4FingerprintAllowList"
      regex_pattern_set = {
        description = "JA4 Fingerprints of trusted sources:\n\tQualys: t13d8, t12d0, t13d8"
        regexes     = ["^(t13d8213h1_300d6e5c0a97_df252b0bff74|t12d020700_b06afd972a5c_8edcc3fed76b|t13d8212h1_300d6e5c0a97_fcc0e56e4c71)$"]
      }
    }
  ]

  managed_rule_group_statement_rules = [
    {
      name            = "AWS-AWSManagedRulesAmazonIpReputationList"
      priority        = 180
      override_action = var.rule_AWS_AWSManagedRulesAmazonIpReputationList_override_action

      statement = {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
        # version     = null

        rule_action_override = {
          # TICKET-ID: block IPs which are untrusted by AWS
          AWSManagedIPReputationList = {
            action = "block"
          }
          # TICKET-ID: Passthrough traffic from known bots
          AWSManagedReconnaissanceList = {
            action = "count"
          }
          # TICKET-ID: block IPs which are untrusted by AWS
          AWSManagedIPDDoSList = {
            action = "block"
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesAmazonIpReputationList"
      }
    },
    {
      name            = "AWS-AWSManagedRulesAnonymousIpList"
      priority        = 185
      override_action = var.rule_AWS_AWSManagedRulesAnonymousIpList_override_action

      statement = {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
        # version     = null

        rule_action_override = {
          AnonymousIPList = {
            action = "challenge"
          }
          HostingProviderIPList = {
            action = "count"
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesAnonymousIpList"
      }
    },
    {
      name            = "AWS-AWSManagedRulesAntiDDoSRuleSet"
      priority        = 200
      override_action = var.rule_AWS_AWSManagedRulesAntiDDoSRuleSet_override_action

      statement = {
        name        = "AWSManagedRulesAntiDDoSRuleSet"
        vendor_name = "AWS"
        version     = "Version_1.0"

        managed_rule_group_configs = [
          {
            login_path   = null
            payload_type = null
            aws_managed_rules_anti_ddos_rule_set = {
              sensitivity_to_block = "LOW"
              client_side_action_config = {
                challenge = {
                  sensitivity     = "MEDIUM"
                  usage_of_action = "ENABLED"
                  exempt_uri_regular_expression = [
                    {
                      # TICKET-ID: first match excludes images api of blackout on wms from triggering DDOS rulesets as there is heavy image collection happening
                      regex_string = "/api/v[^/]+/.+|\\.(acc|avi|css|gif|ico|jpe?g|js|json|mp[34]|ogg|otf|pdf|png|tiff?|ttf|webm|webp|woff2?|xml)$"
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
    /* { # DACTIVATED: bot control. Activate if needed
      name            = "AWS-AWSManagedRulesBotControlRuleSet"
      priority        = 175
      override_action = var.rule_AWS_AWSManagedRulesBotControlRuleSet_override_action

      statement = {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"
        version     = "Version_3.3"

        / * Add or remove headers to classify bot traffic
        rule_action_override = {
          CategoryHttpLibrary = {
            action = "count"
            custom_response = {
              response_code = "404"
              response_header = { name = "example-1", value = "example-1" }
            }
          }
          SignalNonBrowserUserAgent = {
            action = "count"
            custom_request_handling = {
              insert_header = { name = "example-2", value = "example-2" }
            }
          }
        } * /

        / * Add optional header checks to bypass bot control
        scope_down_not_statement_enabled = true
        scope_down_statement = {
          byte_match_statement = {
            field_to_match = { single_header = { name = "x-bypass-token" } }
            positional_constraint = "EXACTLY"
            search_string         = "TEST_TOKEN"
            text_transformation = [ { priority = 20, type = "NONE" } ]
          }
        } * /
        managed_rule_group_configs = [
          {
            login_path   = null
            payload_type = null
            aws_managed_rules_bot_control_rule_set = {
              # true doesnt work for inspection level COMMON. flipped to false on next apply
              enable_machine_learning = true
              inspection_level        = "TARGETED"
            }
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesBotControlRuleSet"
      }
    }, */
    {
      name            = "AWS-AWSManagedRulesCommonRuleSet"
      priority        = 420
      override_action = var.rule_AWS_AWSManagedRulesCommonRuleSet_override_action

      statement = {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
        version     = "Version_1.20"

        rule_action_override = {
          NoUserAgent_HEADER = {
            action = "count"
          }
          UserAgent_BadBots_HEADER = {
            action = "block"
          }
          SizeRestrictions_QUERYSTRING = {
            action = "count"
          }
          SizeRestrictions_Cookie_HEADER = {
            action = "count"
          }
          SizeRestrictions_BODY = {
            action = "count"
          }
          SizeRestrictions_URIPATH = {
            action = "count"
          }
          EC2MetaDataSSRF_BODY = {
            action = "block"
          }
          EC2MetaDataSSRF_COOKIE = {
            action = "block"
          }
          EC2MetaDataSSRF_URIPATH = {
            action = "block"
          }
          EC2MetaDataSSRF_QUERYARGUMENTS = {
            action = "block"
          }
          GenericLFI_QUERYARGUMENTS = {
            action = "block"
          }
          GenericLFI_URIPATH = {
            action = "block"
          }
          GenericLFI_BODY = {
            action = "count"
          }
          RestrictedExtensions_URIPATH = {
            action = "count"
          }
          RestrictedExtensions_QUERYARGUMENTS = {
            action = "count"
          }
          GenericRFI_QUERYARGUMENTS = {
            action = "count"
          }
          GenericRFI_BODY = {
            action = "count"
          }
          GenericRFI_URIPATH = {
            action = "count"
          }
          CrossSiteScripting_COOKIE = {
            action = "count"
          }
          CrossSiteScripting_QUERYARGUMENTS = {
            action = "block"
          }
          CrossSiteScripting_BODY = {
            action = "count"
          }
          CrossSiteScripting_URIPATH = {
            action = "block"
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesCommonRuleSet"
      }
    },
    {
      name            = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
      priority        = 430
      override_action = var.rule_AWS_AWSManagedRulesKnownBadInputsRuleSet_override_action

      statement = {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
        version     = "Version_1.24"

        rule_action_override = {
          JavaDeserializationRCE_BODY = {
            action = "block"
          }

          JavaDeserializationRCE_URIPATH = {
            action = "block"
          }

          JavaDeserializationRCE_QUERYSTRING = {
            action = "block"
          }

          JavaDeserializationRCE_HEADER = {
            action = "block"
          }

          Host_localhost_HEADER = {
            action = "block"
          }

          PROPFIND_METHOD = {
            action = "block"
          }

          ExploitablePaths_URIPATH = {
            action = "block"
          }

          Log4JRCE_QUERYSTRING = {
            action = "block"
          }

          Log4JRCE_BODY = {
            action = "block"
          }

          Log4JRCE_URIPATH = {
            action = "block"
          }

          Log4JRCE_HEADER = {
            action = "block"
          }

          ReactJSRCE_BODY = {
            action = "block"
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
      }
    },
    {
      name            = "AWS-AWSManagedRulesLinuxRuleSet"
      priority        = 450
      override_action = var.rule_AWS_AWSManagedRulesLinuxRuleSet_override_action

      statement = {
        name        = "AWSManagedRulesLinuxRuleSet"
        vendor_name = "AWS"
        version     = "Version_2.6"

        rule_action_override = {
          LFI_URIPATH = {
            action = "block"
          }
          LFI_QUERYSTRING = {
            action = "block"
          }
          LFI_HEADER = {
            action = "block"
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesLinuxRuleSet"
      }
    },
    {
      name            = "AWS-AWSManagedRulesSQLiRuleSet"
      priority        = 440
      override_action = var.rule_AWS_AWSManagedRulesSQLiRuleSet_override_action

      statement = {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
        version     = "Version_1.3"
        rule_action_override = {
          SQLiExtendedPatterns_QUERYARGUMENTS = {
            action = "block"
          }

          SQLi_QUERYARGUMENTS = {
            action = "block"
          }

          SQLi_BODY = {
            action = "block"
          }

          SQLi_COOKIE = {
            action = "block"
          }

          SQLi_URIPATH = {
            action = "block"
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "AWS-AWSManagedRulesSQLiRuleSet"
      }
    }
  ]

  # Regex Pattern Set Reference Rules
  regex_pattern_set_reference_statement_rules = [
    { # Allows Let's Encrpyt traffic to connect and other URI paths
      name     = "Custom-UriPathAllowList"
      priority = 69
      action   = "allow"

      statement = {
        # Reference reusable regex_pattern_set
        set_name = "Custom-UriPathAllowList"

        field_to_match = {
          uri_path = true
        }
        text_transformation = [
          {
            priority = 0
            type     = "NONE"
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-UriPathAllowList"
      }
    },
    { # TICKET-ID: Allow traffic as based on JA4 (for Qualys scans from NL i.e. if IP allowlist doesn't trigger)
      name     = "Custom-FingerprintAllowList"
      priority = 70
      action   = "allow"

      statement = {
        set_name = "Custom-JA4FingerprintAllowList"

        field_to_match = {
          ja4_fingerprint = {
            fallback_behavior = "NO_MATCH"
          }
        }
        text_transformation = [
          {
            priority = 0
            type     = "NONE"
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-FingerprintAllowList"
      }
    },
    { # TICKET-ID: Block traffic to domains not supported by the application and also protect vulnerability exploits
      name     = "Custom-UnknownHostBlocklist"
      priority = 195
      action   = var.rule_Custom_UnknownHostBlocklist_override_action

      statement = {
        regex_pattern_set = {
          regexes = ["^(ec2-.*\\.amazonaws\\.com|.*\\.s3\\.amazonaws\\.com|\\d+\\.\\d+\\.\\d+\\.\\d+|localhost|.*\\.(domainnotsupported1|domainnotsupported2)|)$"]
        }
        field_to_match = {
          single_header = { name = "host" }
        }
        text_transformation = [
          {
            priority = 0
            type     = "LOWERCASE"
          },
          {
            priority = 1
            type     = "COMPRESS_WHITE_SPACE"
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-UnknownHostBlocklist"
      }
    },
    { # TICKET-ID: Block traffic presenting itself as XYZ user agent as it is identified as malicious
      name     = "Custom-UserAgentBlocklist"
      priority = 190
      action   = var.rule_Custom_UserAgentBlocklist_override_action

      statement = {
        regex_pattern_set = {
          regexes = ["^(XYZ)$"]
        }
        field_to_match = {
          single_header = { name = "user-agent" }
        }
        text_transformation = [
          {
            priority = 0
            type     = "LOWERCASE"
          },
          {
            priority = 1
            type     = "COMPRESS_WHITE_SPACE"
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-UserAgentBlocklist"
      }
    },

  ]

  # IP Set Reference Rules
  ip_set_reference_statement_rules = [
    {
      name     = "Custom-IPV4Allowlist"
      priority = 50
      action   = var.rule_Custom_IPV4Allowlist_override_action

      statement = {
        ip_set = {
          description        = "IPV4 list of IPs to allow before traffic validation and ratelimiting occurs"
          ip_address_version = "IPV4"
          addresses = [
            # TICKET-ID: Adds allow list for customer owned subnet
            "100.200.192.0/20", # - 100.200.207.255: Customer Net
            # TICKET-ID: Add allows for Qualys vulnerabilty scannner + fallback IP as mentioned in documentation
            "141.144.196.156/32",
            "158.101.209.126/32",
            # Trust my own companies public IP
            #"MYCOMPANYIP/32"
          ]
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-IPV4Allowlist"
      }
    },
    {
      name     = "Custom-IPV4LabelEC2Public"
      priority = 40
      action   = "count"

      statement = {
        ip_set = {
          description        = "IPV4 list of own Elastic IPs originating from AWS network. These might change through autorotation if not fixed."
          ip_address_version = "IPV4"
          addresses = [
            "3.67.124.124/32",
            "63.180.238.110/32"
          ]
        }
      }

      rule_label = ["iv:detected:ec2public", "iv:sensitivity:low:ipv4"]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-IPV4LabelEC2Public"
      }
    },
    {
      name     = "Custom-IPV6Allowlist"
      priority = 60
      action   = "allow"

      statement = {
        ip_set = {
          description        = "IPV6 list of IPs to allow before traffic validation and ratelimiting occurs"
          ip_address_version = "IPV6"
          addresses          = []
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-IPV6Allowlist"
      }
    },
    {
      name     = "Custom-IPV4Blocklist"
      priority = 150
      action   = "block"

      statement = {
        ip_set = {
          description        = "IPV4 list of IPs to block without further checks"
          ip_address_version = "IPV4"
          addresses          = []
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-IPV4Blocklist"
      }
    },
    {
      name     = "Custom-IPV6Blocklist"
      priority = 160
      action   = "block"

      statement = {
        ip_set = {
          description        = "IPV6 list of IPs to block without further checks"
          ip_address_version = "IPV6"
          addresses          = []
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-IPV6Blocklist"
      }
    }
  ]

  # Nested Statements to Control other Rules
  nested_statement_rules = [
    {
      name     = "Custom-NestedMatchMethodWrite"
      priority = 210
      action   = "count"

      statement = {
        or_statement = {
          statements = [
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "POST"
                field_to_match = {
                  method = true
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "NONE"
                  }
                ]
              })
            },
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "PUT"
                field_to_match = {
                  method = true
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "NONE"
                  }
                ]
              })
            },
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "DELETE"
                field_to_match = {
                  method = true
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "NONE"
                  }
                ]
              })
            },
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "PURGE"
                field_to_match = {
                  method = true
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "NONE"
                  }
                ]
              })
            }
          ]
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-NestedMatchMethodWrite"
      }

      rule_label = ["iv:method:write"]
    },
    {
      name     = "Custom-NestedMatchMethodRead"
      priority = 220
      action   = "count"

      statement = {
        or_statement = {
          statements = [
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "GET"
                field_to_match = {
                  method = true
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "NONE"
                  }
                ]
              })
            },
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "HEAD"
                field_to_match = {
                  method = true
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "NONE"
                  }
                ]
              })
            }
          ]
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-NestedMatchMethodRead"
      }

      rule_label = ["iv:method:read"]
    },

    { # TICKET-ID: Label traffic as sensitive based on previous rule evaluations, especially IP reputation
      # TICKET-ID: Include JA4 fingerprints missing as classifier for traffic to handle with higher sensitivity
      name     = "Custom-RateBasedLabelSensitivityHigh"
      priority = 295
      action   = "count"

      statement = {
        or_statement = {
          statements = [
            {
              type = "label_match_statement"
              statement = jsonencode({
                scope = "NAMESPACE"
                key   = "awswaf:managed:aws:amazon-ip-list:"
              })
            },
            {
              type = "label_match_statement"
              statement = jsonencode({
                scope = "NAMESPACE"
                key   = "awswaf:managed:aws:anonymous-ip-list:"
              })
            },
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "-"

                field_to_match = {
                  ja3_fingerprint = {
                    fallback_behavior = "MATCH"
                  }
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "COMPRESS_WHITE_SPACE"
                  }
                ]
              })
            },
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "-"

                field_to_match = {
                  ja4_fingerprint = {
                    fallback_behavior = "MATCH"
                  }
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "COMPRESS_WHITE_SPACE"
                  }
                ]
              })
            },
          ]
        }
      }

      rule_label = ["iv:sensitivity:high:ratelimit"]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-RateBasedLabelSensitivityHigh"
      }
    },
    { # TICKET-ID: Detects scans originating from tenable
      name     = "Custom-Event-TICKET-ID-TenableScan"
      priority = 285
      action   = "count"

      statement = {
        and_statement = {
          statements = [
            {
              type = "label_match_statement"
              statement = jsonencode({
                scope = "LABEL"
                key   = "awswaf:managed:aws:bot-control:signal:cloud_service_provider:aws"
              })
            },
            {
              type = "label_match_statement"
              statement = jsonencode({
                scope = "LABEL"
                key   = "awswaf:clientip:geo:country:IE"
              })
            },
            {
              type = "size_constraint_statement"
              statement = jsonencode({
                size                = "1"
                comparison_operator = "GT"

                field_to_match = {
                  single_header = { name = "x-tenable-was-scan-id" }
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "COMPRESS_WHITE_SPACE"
                  }
                ]
              })
            }
          ]
        }
      }

      rule_label = ["iv:detected:tenable", "iv:event:TICKET-ID"]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-Event-TICKET-ID-TenableScan"
      }
    },
    { # TICKET-ID: Vulnerability scan event from single source identified by JA4 fingerprint
      name     = "Custom-Event-TICKET-ID-VulnerabilityScan"
      priority = 286
      action   = "count"

      statement = {
        or_statement = {
          statements = [
            {
              type = "byte_match_statement"
              statement = jsonencode({
                positional_constraint = "EXACTLY"
                search_string         = "REPLACE_WITH_JA4_FINGERPRINT"

                field_to_match = {
                  ja4_fingerprint = {
                    fallback_behavior = "NO_MATCH"
                  }
                }
                text_transformation = [
                  {
                    priority = 0
                    type     = "NONE"
                  }
                ]
              })
            },
            {
              type = "ip_set_reference_statement"
              statement = jsonencode({
                set_name = "Custom-Event-TICKET-ID-VulnerabilityScan"
              })
            }
          ]
        }
      }

      rule_label = ["iv:event:TICKET-ID"]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-Event-TICKET-ID-VulnerabilityScan"
      }
    },
  ]


  # Rate Based Rules
  /* Example for a global rate limit 
    {
      name     = "Custom-GlobalRateBasedRule"
      action   = "count"
      priority = 310
      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header = {
          name  = "Retry-After"
          value = "300"
        }
      }

      statement = {
        limit                 = 1000
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-GlobalRateBasedRule"
      }
    },*/

  rate_based_statement_rules = [
    { # TICKET-ID: rate limit read traffic from non Europe/DACH regions early 
      name     = "Custom-RateBasedRuleReadSensitivityHigh"
      action   = var.rule_Custom_RateBasedRuleReadSensitivityHigh_override_action
      priority = 305

      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header          = { name = "Retry-After", value = "300" }
      }
      statement = {
        limit                 = 250
        aggregate_key_type    = "IP"
        evaluation_window_sec = 60
        scope_down_statement = {
          and_statement = {
            statements = [
              {
                type = "label_match_statement"
                statement = jsonencode({
                  scope = "NAMESPACE"
                  key   = "iv:sensitivity:high:"
                })
              },
              {
                type = "not_label_match_statement"
                statement = jsonencode({
                  scope = "NAMESPACE"
                  key   = "iv:sensitivity:low:"
                })
              },
              {
                type = "label_match_statement"
                statement = jsonencode({
                  scope = "LABEL"
                  key   = "iv:method:read"
                })
              },
            ]
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-RateBasedRuleReadSensitivityHigh"
      }
    },
    { # TICKET-ID: rate limit write traffic from non Europe/DACH regions early
      name     = "Custom-RateBasedRuleWriteSensitivityHigh"
      action   = var.rule_Custom_RateBasedRuleWriteSensitivityHigh_override_action
      priority = 310

      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header          = { name = "Retry-After", value = "300" }
      }

      statement = {
        limit                 = 60
        aggregate_key_type    = "IP"
        evaluation_window_sec = 60
        scope_down_statement = {
          and_statement = {
            statements = [
              {
                type = "label_match_statement"
                statement = jsonencode({
                  scope = "NAMESPACE"
                  key   = "iv:sensitivity:high:"
                })
              },
              {
                type = "not_label_match_statement"
                statement = jsonencode({
                  scope = "NAMESPACE"
                  key   = "iv:sensitivity:low:"
                })
              },
              {
                type = "label_match_statement"
                statement = jsonencode({
                  scope = "LABEL"
                  key   = "iv:method:write"
                })
              },
            ]
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-RateBasedRuleWriteSensitivityHigh"
      }
    },
    {
      name     = "Custom-RateBasedRuleRead"
      action   = var.rule_Custom_RateBasedRuleRead_override_action
      priority = 320

      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header          = { name = "Retry-After", value = "300" }
      }

      statement = {
        limit                 = 1500
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300
        scope_down_statement = {
          and_statement = {
            statements = [
              {
                type = "not_label_match_statement"
                statement = jsonencode({
                  scope = "NAMESPACE"
                  key   = "iv:sensitivity:"
                })
              },
              {
                type = "label_match_statement"
                statement = jsonencode({
                  scope = "LABEL"
                  key   = "iv:method:read"
                })
              },
            ]
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-RateBasedRuleRead"
      }
    },
    {
      name     = "Custom-RateBasedRuleWrite"
      action   = var.rule_Custom_RateBasedRuleWrite_override_action
      priority = 330

      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header          = { name = "Retry-After", value = "300" }
      }

      statement = {
        limit                 = 300
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300
        scope_down_statement = {
          and_statement = {
            statements = [
              {
                type = "not_label_match_statement"
                statement = jsonencode({
                  scope = "NAMESPACE"
                  key   = "iv:sensitivity:"
                })
              },
              {
                type = "label_match_statement"
                statement = jsonencode({
                  scope = "LABEL"
                  key   = "iv:method:write"
                })
              },
            ]
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-RateBasedRuleWrite"
      }
    },
    {
      name     = "Custom-ManagedIPDDoSRateLimit"
      priority = 300
      action   = var.rule_Custom_ManagedIPDDoSRateLimit_override_action

      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header          = { name = "Retry-After", value = "300" }
      }

      statement = {
        limit                 = 1000
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300
        scope_down_statement = {
          and_statement = {
            statements = [
              {
                type = "not_label_match_statement"
                statement = jsonencode({
                  scope = "NAMESPACE"
                  key   = "iv:sensitivity:low:"
                })
              },
              {
                type = "label_match_statement"
                statement = jsonencode({
                  scope = "LABEL"
                  key   = "awswaf:managed:aws:amazon-ip-list:AWSManagedIPDDoSList"
                })
              },
            ]
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-ManagedIPDDoSRateLimit"
      }
    }
  ]

  # Geo Match Rules
  geo_match_statement_rules = [
    { # TICKET-ID: Adds geoblocks for untrusted origin countries
      name     = "Custom-GeoBlockList"
      priority = 170
      action   = "block"

      statement = { country_codes = ["CU", "IR", "KP", "RU", "SY", "VE"] }

      rule_label = ["iv:geo:block"]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-GeoBlockList"
      }
    },
    { # TICKET-ID: label traffic from non Europe/DACH regions for sensitive rulesets (i.e. rate limiting)
      # TICKET-ID: adds Netherlands as trusted source as Qualys scans originate from Oracle cloud hosted there
      name     = "Custom-GeoSensitivityHigh"
      priority = 270
      action   = "count"

      not_statement = { country_codes = ["DE", "CH", "LU", "AT", "FR", "GB", "NL"] }

      rule_label = ["iv:sensitivity:high:geo"]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-GeoSensitivityHigh"
      }
    }
  ]

  geo_allowlist_statement_rules = [
    {
      name     = "Custom-GeoSensitivityLow"
      priority = 250
      action   = "count"

      statement = { country_codes = ["DE"] }

      rule_label = ["iv:sensitivity:low:geo"]

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-GeoSensitivityLow"
      }
    }
  ]

  # Size Constraint Rules
  size_constraint_statement_rules = [
    {
      name     = "Custom-SizeConstraintBody"
      action   = "count"
      priority = 610

      statement = {
        comparison_operator = "GT"
        size                = 16384
        field_to_match = {
          body = {
            oversize_handling = "MATCH"
          }
          # for example:
          # all_query_arguments = {} 
        }
        text_transformation = [{ type = "COMPRESS_WHITE_SPACE", priority = 1 }]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-SizeConstraintBody"
      }
    }
  ]

  # XSS Rules
  xss_match_statement_rules = [
    {
      name     = "Custom-XSSProtectionUri"
      action   = var.rule_Custom_XSSProtectionUri_override_action
      priority = 710

      statement = {
        field_to_match = {
          uri_path = true
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
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-XSSProtectionUri"
      }
    },
    {
      name     = "Custom-XSSProtectionHeaderReferer"
      action   = var.rule_Custom_XSSProtectionHeaderReferer_override_action
      priority = 711

      statement = {
        field_to_match = {
          single_header = {
            name = "referer"
          }
        }
        text_transformation = [
          {
            type     = "HTML_ENTITY_DECODE"
            priority = 1
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-XSSProtectionHeaderReferer"
      }
    },
  ]

  # SQLi Rules
  sqli_match_statement_rules = [

    {
      name     = "Custom-SQLiProtectionUri"
      action   = var.rule_Custom_SQLiProtectionUri_override_action
      priority = 750

      statement = {
        field_to_match = {
          uri_path = true
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
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-SQLiProtectionUri"
      }
    },
    {
      name     = "Custom-SQLiProtectionHeaderReferer"
      action   = var.rule_Custom_SQLiProtectionHeaderReferer_override_action
      priority = 751

      statement = {
        field_to_match = {
          single_header = {
            name = "referer"
          }
        }
        text_transformation = [
          {
            type     = "HTML_ENTITY_DECODE"
            priority = 1
          }
        ]
      }

      visibility_config = {
        cloudwatch_metrics_enabled = true
        sampled_requests_enabled   = true
        metric_name                = "Custom-SQLiProtectionHeaderReferer"
      }
    },
  ]
}

/* Example for path based rate limiting
    {
      name     = "Custom-RateBasedRulePath"
      action   = "count"
      priority = 90

      custom_response = {
        response_code            = "429"
        custom_response_body_key = "rate_limit_exceeded"
        response_header = { name = "Retry-After", value = "300" }
      }
      statement = {
        limit                 = 50
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300
        scope_down_statement = {
          or_statement = {
            statement = {
              byte_match_statement = {
                positional_constraint = "STARTS_WITH"
                search_string         = "/login"
                field_to_match        = { 
                  uri_path = true 
                }
                text_transformation   = [{ 
                  priority = 0
                  type = "NONE" 
                }]
              }
            }
            statement = { ... }
          }
        }
      }

      visibility_config = {
        cloudwatch_metrics_enabled = false
        sampled_requests_enabled   = false
        metric_name                = "Custom-RateBasedRulePath"
      }
    },*/