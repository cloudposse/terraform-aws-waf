resource "aws_wafv2_web_acl_association" "default" {
  count = module.this.enabled && length(var.association_resource_arns) > 0 ? length(var.association_resource_arns) : 0

  resource_arn = var.association_resource_arns[count.index]
  web_acl_arn  = join("", aws_wafv2_web_acl.default.*.arn)
}

module "kinesis_iam_role" {
  source                = "git@github.com:humn-ai/tf-mod-aws-iam-role?ref=tags/0.0.3"
  enabled               = module.this.enabled
  attributes            = ["role"]
  name                  = module.this.name
  label_order           = module.this.label_order
  trusted_role_actions  = ["sts:AssumeRole"]
  trusted_role_services = ["firehose.amazonaws.com"]
  max_session_duration  = 7200
  policy_config         = var.policy_config
}

resource "aws_kinesis_firehose_delivery_stream" "default" {
  name        = module.kinesis.id
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = module.kinesis_iam_role.role_arn
    bucket_arn = var.bucket_arn
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "default" {
  count = module.this.enabled && length(var.log_destination_configs) > 0 ? 1 : 0

  log_destination_configs = var.log_destination_configs
  resource_arn            = join("", aws_wafv2_web_acl.default.*.arn)

  dynamic "redacted_fields" {
    for_each = var.redacted_fields

    content {
      dynamic "method" {
        for_each = redacted_fields.value.method_enabled ? [1] : []

        content {
        }
      }

      dynamic "query_string" {
        for_each = redacted_fields.value.query_string_enabled ? [1] : []

        content {
        }
      }

      dynamic "uri_path" {
        for_each = redacted_fields.value.uri_path_enabled ? [1] : []

        content {
        }
      }

      dynamic "single_header" {
        for_each = lookup(redacted_fields.value, "single_header", null) != null ? toset(redacted_fields.value.single_header) : []
        content {
          name = single_header.value
        }
      }
    }
  }
}
