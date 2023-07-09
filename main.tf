locals {
  enabled = module.this.enabled
}

# Do not use this resource to associate a WAFv2 Web ACL with a Cloudfront Distribution.
# The AWS API call backing this resource notes that you should use the `web_acl_id` property on the `cloudfront_distribution` instead.
# For more details, refer to:
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association
# https://docs.aws.amazon.com/waf/latest/APIReference/API_AssociateWebACL.html
resource "aws_wafv2_web_acl_association" "default" {
  count = local.enabled && length(var.association_resource_arns) > 0 ? length(var.association_resource_arns) : 0

  resource_arn = var.association_resource_arns[count.index]
  web_acl_arn  = one(aws_wafv2_web_acl.default[*].arn)
}

# To start logging from a WAFv2 Web ACL, you need to create an Amazon Kinesis Data Firehose resource,
# such as the `aws_kinesis_firehose_delivery_stream` resource.
# Make sure to create the firehose with a PUT source (not a stream) in the region where you are operating.
# If you are capturing logs for Amazon CloudFront, create the firehose in the US East (N. Virginia) region.
# It is important to name the data firehose, CloudWatch log group, and/or S3 bucket with a prefix of `aws-waf-logs-`.
resource "aws_wafv2_web_acl_logging_configuration" "default" {
  count = local.enabled && length(var.log_destination_configs) > 0 ? 1 : 0

  resource_arn            = one(aws_wafv2_web_acl.default[*].arn)
  log_destination_configs = var.log_destination_configs

  dynamic "redacted_fields" {
    for_each = var.redacted_fields

    content {
      dynamic "method" {
        for_each = redacted_fields.value.method ? [true] : []
        content {}
      }

      dynamic "query_string" {
        for_each = redacted_fields.value.query_string ? [true] : []
        content {}
      }

      dynamic "uri_path" {
        for_each = redacted_fields.value.uri_path ? [true] : []
        content {}
      }

      dynamic "single_header" {
        for_each = lookup(redacted_fields.value, "single_header", null) != null ? toset(redacted_fields.value.single_header) : []
        content {
          name = single_header.value
        }
      }
    }
  }

  dynamic "logging_filter" {
    for_each = var.logging_filter != null ? [true] : []

    content {
      default_behavior = var.logging_filter.default_behavior

      dynamic "filter" {
        for_each = var.logging_filter.filter

        content {
          behavior    = filter.value.behavior
          requirement = filter.value.requirement

          dynamic "condition" {
            for_each = filter.value.condition

            content {
              dynamic "action_condition" {
                for_each = condition.value.action_condition != null ? [true] : []
                content {
                  action = condition.value.action_condition.action
                }
              }
              dynamic "label_name_condition" {
                for_each = condition.value.label_name_condition != null ? [true] : []
                content {
                  label_name = condition.value.label_name_condition.label_name
                }
              }
            }
          }
        }
      }
    }
  }
}
