output "id" {
  description = "The ID of the WAF WebACL."
  value       = one(aws_wafv2_web_acl.default[*].id)
}

output "arn" {
  description = "The ARN of the WAF WebACL."
  value       = one(aws_wafv2_web_acl.default[*].arn)
}

output "capacity" {
  description = "The web ACL capacity units (WCUs) currently being used by this web ACL."
  value       = one(aws_wafv2_web_acl.default[*].capacity)
}

output "logging_config_id" {
  description = "The ARN of the WAFv2 Web ACL logging configuration."
  value       = one(aws_wafv2_web_acl_logging_configuration.default[*].id)
}
