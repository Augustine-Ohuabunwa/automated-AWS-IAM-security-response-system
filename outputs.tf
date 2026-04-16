output "sns_topic_arn" {
  description = "ARN of the SNS topic for security alert notifications"
  value       = aws_sns_topic.security_alerts.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.name
}

output "lambda_function_name" {
  description = "Name of the Lambda function that disables exposed IAM credentials"
  value       = aws_lambda_function.credential_killswitch.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.credential_killswitch.arn
}

output "lambda_role_arn" {
  description = "ARN of the IAM role used by the Lambda function"
  value       = aws_iam_role.lambda_execution.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule that detects AWS Health IAM exposure events"
  value       = aws_cloudwatch_event_rule.health_iam_exposure.name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.health_iam_exposure.arn
}

output "dlq_url" {
  description = "URL of the Dead Letter Queue for failed Lambda invocations"
  value       = aws_sqs_queue.lambda_dlq.url
}

output "dlq_arn" {
  description = "ARN of the Dead Letter Queue"
  value       = aws_sqs_queue.lambda_dlq.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for Lambda function logs"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.lambda_logs.arn
}

output "deployment_region" {
  description = "AWS region where the infrastructure is deployed"
  value       = var.aws_region
}
