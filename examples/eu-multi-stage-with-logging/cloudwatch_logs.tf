module "cloudwatch_logs" {
  source = "cloudposse/cloudwatch-logs/aws"
  # Cloud Posse recommends pinning every module to a specific version
  # version = "x.x.x"

  # Context
  enabled     = true
  environment = var.environment
  stage       = var.stage
  name        = var.name
  namespace   = "aws-waf-logs"

  retention_in_days = 7

  principals = {
    "Service" : [
      "delivery.logs.amazonaws.com"
    ]
  }
  additional_permissions = [
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ]
}
