terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Optional KMS key for Lambda and logs encryption
resource "aws_kms_key" "lambda" {
  count       = var.create_kms_key ? 1 : 0
  description = "KMS key for ${var.name_prefix} MCSPM Lambda and logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowLambdaAccess"
        Effect = "Allow"
        Principal = { AWS = aws_iam_role.lambda.arn }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
  tags = var.tags
}

resource "aws_kms_alias" "lambda" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${var.name_prefix}-mcspm-lambda"
  target_key_id = aws_kms_key.lambda[0].key_id
}

data "aws_caller_identity" "current" {}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-mcspm-dlq"
  message_retention_seconds = 1209600
  tags                      = var.tags
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name_prefix}-mcspm-forwarder"
  retention_in_days = 30
  kms_key_id        = var.create_kms_key ? aws_kms_key.lambda[0].arn : null
  tags              = var.tags
}

resource "aws_iam_role" "lambda" {
  name                 = "${var.name_prefix}-mcspm-lambda-role"
  permissions_boundary = var.iam_boundary_policy_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "lambda" {
  name = "${var.name_prefix}-mcspm-lambda-policy"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = ["secretsmanager:GetSecretValue"],
        Resource = var.splunk_hec_token_secret_arn
      },
      {
        Effect = "Allow",
        Action = ["kms:Decrypt", "kms:DescribeKey"],
        Resource = var.create_kms_key ? aws_kms_key.lambda[0].arn : (var.lambda_kms_key_arn != null ? var.lambda_kms_key_arn : "*")
      }
    ]
  })
}

# VPC permissions for Lambda if VPC config provided
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  count      = length(var.vpc_subnet_ids) > 0 ? 1 : 0
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src"
  output_path = "${path.module}/.tmp/mcspm_src.zip"
}

resource "aws_lambda_function" "forwarder" {
  function_name    = "${var.name_prefix}-mcspm-forwarder"
  role             = aws_iam_role.lambda.arn
  handler          = "aws_lambda_forwarder/handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb
  reserved_concurrent_executions = var.lambda_reserved_concurrency
  kms_key_arn = var.create_kms_key ? aws_kms_key.lambda[0].arn : var.lambda_kms_key_arn
  
  dynamic "vpc_config" {
    for_each = length(var.vpc_subnet_ids) > 0 ? [1] : []
    content {
      subnet_ids         = var.vpc_subnet_ids
      security_group_ids = var.vpc_security_group_ids
    }
  }
  
  environment {
    variables = {
      SPLUNK_HEC_URL    = var.splunk_hec_url
      AWS_SECRETS_MANAGER_HEC_TOKEN_ARN = var.splunk_hec_token_secret_arn
      SPLUNK_SOURCETYPE = "mcspm:finding"
      SPLUNK_SOURCE     = "aws-security-hub"
      SPLUNK_INDEX      = var.splunk_index
      AWS_ACCOUNT_ID    = data.aws_caller_identity.current.account_id
      AWS_REGION        = var.region
    }
  }
  depends_on = [aws_cloudwatch_log_group.lambda]

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "${var.name_prefix}-mcspm-shub-rule"
  description = "Route Security Hub findings to forwarder"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"],
    detail_type = ["Security Hub Findings - Imported"],
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "to_lambda" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "lambda"
  arn       = aws_lambda_function.forwarder.arn
}

resource "aws_lambda_permission" "allow_events" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.forwarder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_findings.arn
}

resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0
}
