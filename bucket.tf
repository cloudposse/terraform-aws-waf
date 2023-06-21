module "waf_bucket" {
  count  = var.create_logging_bucket ? 1 : 0
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-s3-bucket.git?ref=v3.4.0"

  bucket = "aws-waf-logs-${module.this.environment}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  lifecycle_rule = var.logging_bucket_lifecycle_rule != null ? jsondecode(var.logging_bucket_lifecycle_rule) : []

  tags = module.this.tags
}