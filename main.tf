resource "aws_wafv2_web_acl_association" "default" {
  count = module.this.enabled && length(var.association_resource_arns) > 0 ? length(var.association_resource_arns) : 0

  resource_arn = var.association_resource_arns[count.index]
  web_acl_arn  = join("", aws_wafv2_web_acl.default.*.arn)
}

resource "aws_kinesis_firehose_delivery_stream" "default" {
  name        = "aws-waf-logs-${var.name}-${element(module.kinesis.attributes, 0)}" //https://github.com/pulumi/pulumi-aws/issues/1214#issuecomment-891868939
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = var.role_arn
    bucket_arn = var.bucket_arn
    prefix     = "${module.this.id}/"
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "default" {
  count = module.this.enabled ? 1 : 0

  log_destination_configs = [aws_kinesis_firehose_delivery_stream.default.arn]
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
