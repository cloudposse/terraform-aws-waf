name        = "waf"
environment = "fra"
stage       = "staging"
region      = "eu-central-1"

# Unset for automated testing
# association_resource_arns = ["arn:aws:elasticloadbalancing:eu-central-1:ACCOUNTID:loadbalancer/app/alb..."]

# Managed Rules
rule_AWS_AWSManagedRulesAmazonIpReputationList_override_action = null
rule_AWS_AWSManagedRulesAnonymousIpList_override_action        = null
rule_AWS_AWSManagedRulesSQLiRuleSet_override_action            = null
rule_AWS_AWSManagedRulesAntiDDoSRuleSet_override_action        = null
rule_AWS_AWSManagedRulesCommonRuleSet_override_action          = null
rule_AWS_AWSManagedRulesKnownBadInputsRuleSet_override_action  = null
rule_AWS_AWSManagedRulesLinuxRuleSet_override_action           = null

# Custom Rules
rule_Custom_UnknownHostBlocklist_override_action        = "block"
rule_Custom_UserAgentBlocklist_override_action          = "block"
rule_Custom_XSSProtectionUri_override_action            = "block"
rule_Custom_XSSProtectionHeaderReferer_override_action  = "block"
rule_Custom_SQLiProtectionUri_override_action           = "block"
rule_Custom_SQLiProtectionHeaderReferer_override_action = "block"

# Rate Limits
rule_Custom_RateBasedRuleReadSensitivityHigh_override_action  = "challenge"
rule_Custom_RateBasedRuleWriteSensitivityHigh_override_action = "challenge"
rule_Custom_ManagedIPDDoSRateLimit_override_action            = "challenge"