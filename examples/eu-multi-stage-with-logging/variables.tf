# Association resource ARNs
variable "association_resource_arns" {
  type        = list(string)
  default     = []
  description = <<-DOC
    A list of ARNs of the resources to associate with the web ACL.
    This must be an ARN of an Application Load Balancer, Amazon API Gateway stage, or AWS AppSync.

    Do not use this variable to associate a Cloudfront Distribution.
    Instead, you should use the `web_acl_id` property on the `cloudfront_distribution` resource.
    For more details, refer to https://docs.aws.amazon.com/waf/latest/APIReference/API_AssociateWebACL.html
  DOC
  nullable    = false
}

variable "rule_AWS_AWSManagedRulesAmazonIpReputationList_override_action" {
  type     = string
  default  = "count"
  nullable = true
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count", "null"], coalesce(var.rule_AWS_AWSManagedRulesAmazonIpReputationList_override_action, "null"))
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha`, `count` and null."
  }
}

variable "rule_AWS_AWSManagedRulesAnonymousIpList_override_action" {
  type     = string
  default  = "count"
  nullable = true
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count", "null"], coalesce(var.rule_AWS_AWSManagedRulesAnonymousIpList_override_action, "null"))
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha`, `count` and null."
  }
}

variable "rule_AWS_AWSManagedRulesAntiDDoSRuleSet_override_action" {
  type     = string
  default  = "count"
  nullable = true
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count", "null"], coalesce(var.rule_AWS_AWSManagedRulesAntiDDoSRuleSet_override_action, "null"))
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha`, `count` and null."
  }
}

variable "rule_AWS_AWSManagedRulesBotControlRuleSet_override_action" {
  type     = string
  default  = "count"
  nullable = true
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count", "null"], coalesce(var.rule_AWS_AWSManagedRulesBotControlRuleSet_override_action, "null"))
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha`, `count` and null."
  }
}

variable "rule_AWS_AWSManagedRulesCommonRuleSet_override_action" {
  type     = string
  default  = "count"
  nullable = true
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count", "null"], coalesce(var.rule_AWS_AWSManagedRulesCommonRuleSet_override_action, "null"))
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha`, `count` and null."
  }
}

variable "rule_AWS_AWSManagedRulesKnownBadInputsRuleSet_override_action" {
  type     = string
  default  = "count"
  nullable = true
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count", "null"], coalesce(var.rule_AWS_AWSManagedRulesKnownBadInputsRuleSet_override_action, "null"))
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha`, `count` and null."
  }
}

variable "rule_AWS_AWSManagedRulesLinuxRuleSet_override_action" {
  type     = string
  default  = "count"
  nullable = true
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count", "null"], coalesce(var.rule_AWS_AWSManagedRulesLinuxRuleSet_override_action, "null"))
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha`, `count` and null."
  }
}

variable "rule_AWS_AWSManagedRulesSQLiRuleSet_override_action" {
  type     = string
  default  = "count"
  nullable = true
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count", "null"], coalesce(var.rule_AWS_AWSManagedRulesSQLiRuleSet_override_action, "null"))
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha`, `count` and null."
  }
}

variable "rule_Custom_UnknownHostBlocklist_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_UnknownHostBlocklist_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_UserAgentBlocklist_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_UserAgentBlocklist_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_RateBasedRuleReadSensitivityHigh_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_RateBasedRuleReadSensitivityHigh_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_RateBasedRuleWriteSensitivityHigh_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_RateBasedRuleWriteSensitivityHigh_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_RateBasedRuleRead_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_RateBasedRuleRead_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_RateBasedRuleWrite_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_RateBasedRuleWrite_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_ManagedIPDDoSRateLimit_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_ManagedIPDDoSRateLimit_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_XSSProtectionUri_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_XSSProtectionUri_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_XSSProtectionHeaderReferer_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_XSSProtectionHeaderReferer_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_SQLiProtectionUri_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_SQLiProtectionUri_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_SQLiProtectionHeaderReferer_override_action" {
  type    = string
  default = "count"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_SQLiProtectionHeaderReferer_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}

variable "rule_Custom_IPV4Allowlist_override_action" {
  type    = string
  default = "allow"
  validation {
    condition     = contains(["allow", "block", "challenge", "captcha", "count"], var.rule_Custom_IPV4Allowlist_override_action)
    error_message = "Allowed values: `allow`, `block`, `challenge`, `captcha` and `count`."
  }
}