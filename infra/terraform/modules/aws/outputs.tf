output "lambda_function_name" { value = aws_lambda_function.forwarder.function_name }
output "event_rule_arn" { value = aws_cloudwatch_event_rule.security_hub_findings.arn }
output "dlq_url" { value = aws_sqs_queue.dlq.id }
