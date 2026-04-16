terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Purpose     = "SecurityAutomation"
      ManagedBy   = "Terraform"
      Project     = "IAMCredentialExposureResponse"
    }
  }
}

# ============================================================================
# CloudWatch Logs - Create log group first so we can reference it in IAM policy
# ============================================================================

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/iam_leaked_credential_killswitch"
  retention_in_days = var.log_retention_days
  kms_key_id        = null # Use AWS managed key for encryption at rest

  tags = {
    Name = "iam-leaked-credential-killswitch-logs"
  }
}

# ============================================================================
# Dead Letter Queue (DLQ) for Lambda Failures
# ============================================================================

resource "aws_sqs_queue" "lambda_dlq" {
  name                       = "iam-credential-exposure-dlq"
  message_retention_seconds  = var.dlq_retention_days * 86400 # Convert days to seconds
  visibility_timeout_seconds = 300

  # Security: Enable encryption at rest with AWS managed key
  sqs_managed_sse_enabled = true

  tags = {
    Name = "iam-credential-exposure-dlq"
  }
}

# CloudWatch Alarm: Alert when messages enter DLQ (indicates Lambda failures)
resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "iam-credential-dlq-messages-detected"
  alarm_description   = "Alert when failed Lambda invocations are sent to DLQ"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.lambda_dlq.name
  }

  alarm_actions = [aws_sns_topic.security_alerts.arn]

  tags = {
    Name = "dlq-depth-alarm"
  }
}

# ============================================================================
# SNS Topic for Security Alerts
# ============================================================================

resource "aws_sns_topic" "security_alerts" {
  name              = "iam-credential-exposure-alerts"
  display_name      = "IAM Credential Exposure Security Alerts"
  kms_master_key_id = "alias/aws/sns" # Use AWS managed key for encryption at rest

  tags = {
    Name = "iam-credential-exposure-alerts"
  }
}

resource "aws_sns_topic_subscription" "security_team_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_notification_email
}

# ============================================================================
# IAM Role and Policies for Lambda (Least Privilege)
# ============================================================================

# Trust policy: Allow Lambda service to assume this role
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "lambda_execution" {
  name               = "iam-credential-killswitch-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  description        = "Execution role for IAM credential exposure response Lambda"

  tags = {
    Name = "iam-credential-killswitch-lambda-role"
  }
}

# Policy 1: CloudWatch Logs - Scoped to specific log group
data "aws_iam_policy_document" "lambda_logging" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    # Scoped to this specific log group only
    resources = [
      "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "lambda_logging" {
  name   = "cloudwatch-logs-access"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_logging.json
}

# Policy 2: IAM Access Key Management - Least privilege
# Note: IAM actions cannot be scoped to specific users in resource ARN,
# but we add conditions to limit blast radius where possible
data "aws_iam_policy_document" "lambda_iam_access" {
  statement {
    effect = "Allow"
    actions = [
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey"
    ]
    # IAM user resources - cannot scope further without knowing specific users
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }

  # Read-only IAM access to get user details
  statement {
    effect = "Allow"
    actions = [
      "iam:GetUser"
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }
}

resource "aws_iam_role_policy" "lambda_iam_access" {
  name   = "iam-access-key-management"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_iam_access.json
}

# Policy 3: SNS Publish - Scoped to specific topic
data "aws_iam_policy_document" "lambda_sns_publish" {
  statement {
    effect = "Allow"
    actions = [
      "sns:Publish"
    ]
    # Scoped to this specific SNS topic only
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_iam_role_policy" "lambda_sns_publish" {
  name   = "sns-publish-access"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_sns_publish.json
}

# Policy 4: SQS DLQ - Scoped to specific queue (for async invocation failures)
data "aws_iam_policy_document" "lambda_sqs_dlq" {
  statement {
    effect = "Allow"
    actions = [
      "sqs:SendMessage"
    ]
    # Scoped to this specific DLQ only
    resources = [aws_sqs_queue.lambda_dlq.arn]
  }
}

resource "aws_iam_role_policy" "lambda_sqs_dlq" {
  name   = "sqs-dlq-access"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_sqs_dlq.json
}

# Get current AWS account ID for use in IAM policies
data "aws_caller_identity" "current" {}

# ============================================================================
# Lambda Function - IAM Credential Killswitch
# ============================================================================

# Create Python Lambda function code inline
resource "local_file" "lambda_code" {
  filename = "${path.module}/lambda_function.py"
  content  = <<-PYTHON
import json
import boto3
import logging
from datetime import datetime
from typing import Dict, List, Any

# Configure structured JSON logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')

# Environment variables (injected by Terraform)
import os
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Health IAM Credential Exposure Response Handler

    Automatically disables IAM access keys when AWS Health detects exposed credentials.
    Implements idempotent execution to handle duplicate events safely.

    Args:
        event: AWS Health event with exposed credential details
        context: Lambda execution context

    Returns:
        Response dict with status and actions taken
    """

    # Log the incoming event for debugging
    logger.info(json.dumps({
        "message": "Received AWS Health IAM credential exposure event",
        "event_id": event.get('id'),
        "event_time": event.get('time'),
        "detail_type": event.get('detail-type')
    }))

    try:
        # Parse AWS Health event details
        detail = event.get('detail', {})
        affected_entities = detail.get('affectedEntities', [])
        event_arn = event.get('id', 'unknown')
        event_time = event.get('time', datetime.utcnow().isoformat())

        if not affected_entities:
            logger.warning(json.dumps({
                "message": "No affected entities found in Health event",
                "event_arn": event_arn
            }))
            return {
                "statusCode": 200,
                "body": "No affected entities to process"
            }

        actions_taken = []
        errors = []

        # Process each affected IAM user
        for entity in affected_entities:
            entity_value = entity.get('entityValue', '')

            # Extract IAM username from entity value
            # Format can be: "arn:aws:iam::123456789012:user/username" or just "username"
            if '/' in entity_value:
                username = entity_value.split('/')[-1]
            else:
                username = entity_value

            logger.info(json.dumps({
                "message": "Processing affected IAM user",
                "username": username,
                "entity_value": entity_value
            }))

            try:
                # Step 1: List all access keys for this user
                response = iam_client.list_access_keys(UserName=username)
                access_keys = response.get('AccessKeyMetadata', [])

                if not access_keys:
                    logger.info(json.dumps({
                        "message": "No access keys found for user",
                        "username": username
                    }))
                    continue

                # Step 2: Disable each ACTIVE access key
                for key in access_keys:
                    access_key_id = key['AccessKeyId']
                    key_status = key['Status']

                    # Idempotency check: Skip if already inactive
                    if key_status == 'Inactive':
                        logger.info(json.dumps({
                            "message": "Access key already inactive (idempotency)",
                            "username": username,
                            "access_key_id": access_key_id
                        }))
                        actions_taken.append({
                            "username": username,
                            "access_key_id": access_key_id,
                            "action": "already_inactive",
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        continue

                    # Disable the active key (preserve for forensics - do NOT delete)
                    iam_client.update_access_key(
                        UserName=username,
                        AccessKeyId=access_key_id,
                        Status='Inactive'
                    )

                    logger.info(json.dumps({
                        "message": "Successfully disabled access key",
                        "username": username,
                        "access_key_id": access_key_id,
                        "previous_status": key_status
                    }))

                    actions_taken.append({
                        "username": username,
                        "access_key_id": access_key_id,
                        "action": "disabled",
                        "previous_status": key_status,
                        "timestamp": datetime.utcnow().isoformat()
                    })

            except iam_client.exceptions.NoSuchEntityException:
                error_msg = f"IAM user not found: {username}"
                logger.error(json.dumps({
                    "message": error_msg,
                    "username": username
                }))
                errors.append(error_msg)

            except Exception as user_error:
                error_msg = f"Error processing user {username}: {str(user_error)}"
                logger.error(json.dumps({
                    "message": "Error processing IAM user",
                    "username": username,
                    "error": str(user_error)
                }), exc_info=True)
                errors.append(error_msg)

        # Step 3: Send SNS notification to security team
        notification_subject = "ALERT: IAM Credentials Exposed - Automatic Response Taken"
        notification_message = format_sns_message(
            event_arn=event_arn,
            event_time=event_time,
            actions_taken=actions_taken,
            errors=errors
        )

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=notification_subject,
            Message=notification_message
        )

        logger.info(json.dumps({
            "message": "SNS notification sent to security team",
            "topic_arn": SNS_TOPIC_ARN,
            "actions_count": len(actions_taken),
            "errors_count": len(errors)
        }))

        # Return success response
        response = {
            "statusCode": 200,
            "body": json.dumps({
                "message": "IAM credential exposure response completed",
                "actions_taken": actions_taken,
                "errors": errors,
                "event_arn": event_arn
            })
        }

        logger.info(json.dumps({
            "message": "Lambda execution completed successfully",
            "actions_taken": len(actions_taken),
            "errors_count": len(errors)
        }))

        return response

    except Exception as e:
        # Top-level error handling
        error_message = f"Critical error in Lambda handler: {str(e)}"
        logger.error(json.dumps({
            "message": error_message,
            "error_type": type(e).__name__
        }), exc_info=True)

        # Attempt to send error notification to SNS
        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="ERROR: IAM Credential Exposure Response Failed",
                Message=f"Critical error occurred:\n\n{error_message}\n\nEvent: {json.dumps(event, indent=2)}"
            )
        except Exception as sns_error:
            logger.error(f"Failed to send error notification to SNS: {str(sns_error)}")

        # Re-raise to trigger Lambda retry and DLQ
        raise


def format_sns_message(
    event_arn: str,
    event_time: str,
    actions_taken: List[Dict[str, str]],
    errors: List[str]
) -> str:
    """Format detailed SNS notification message for security team"""

    message_lines = [
        "=" * 70,
        "AWS HEALTH: IAM CREDENTIALS EXPOSED - AUTOMATIC RESPONSE",
        "=" * 70,
        "",
        f"Event ARN: {event_arn}",
        f"Event Time: {event_time}",
        f"Response Time: {datetime.utcnow().isoformat()}Z",
        "",
        "ACTIONS TAKEN:",
        "-" * 70
    ]

    if actions_taken:
        for action in actions_taken:
            message_lines.append(f"  User: {action['username']}")
            message_lines.append(f"  Access Key ID: {action['access_key_id']}")
            message_lines.append(f"  Action: {action['action'].upper()}")
            message_lines.append(f"  Timestamp: {action['timestamp']}")
            message_lines.append("")
    else:
        message_lines.append("  No actions were required (all keys already inactive)")
        message_lines.append("")

    if errors:
        message_lines.extend([
            "ERRORS ENCOUNTERED:",
            "-" * 70
        ])
        for error in errors:
            message_lines.append(f"  - {error}")
        message_lines.append("")

    message_lines.extend([
        "NEXT STEPS:",
        "-" * 70,
        "  1. Review CloudWatch Logs for detailed execution logs",
        "  2. Investigate CloudTrail for unauthorized API calls in last 24 hours",
        "  3. Contact affected users to rotate credentials",
        "  4. Review security posture and credential management practices",
        "",
        "This is an automated response from the IAM Credential Killswitch system.",
        "=" * 70
    ])

    return "\n".join(message_lines)
PYTHON
}

# Create deployment package from Lambda code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = local_file.lambda_code.filename
  output_path = "${path.module}/lambda_function.zip"

  depends_on = [local_file.lambda_code]
}

# Lambda function resource
resource "aws_lambda_function" "credential_killswitch" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "iam_leaked_credential_killswitch"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  description      = "Automatically disables IAM access keys when AWS Health detects exposed credentials"

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }

  # Dead letter queue configuration for async invocation failures
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  # CloudWatch Logs configuration
  logging_config {
    log_format = "JSON" # Structured logging for easier querying
    log_group  = aws_cloudwatch_log_group.lambda_logs.name
  }

  tags = {
    Name = "iam-leaked-credential-killswitch"
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy.lambda_logging,
    aws_iam_role_policy.lambda_iam_access,
    aws_iam_role_policy.lambda_sns_publish,
    aws_iam_role_policy.lambda_sqs_dlq
  ]
}

# Configure async invocation settings for reliability
resource "aws_lambda_function_event_invoke_config" "credential_killswitch_async" {
  function_name = aws_lambda_function.credential_killswitch.function_name

  # Retry failed invocations up to 2 times
  maximum_retry_attempts = 2

  # Discard events older than 1 hour (3600 seconds)
  maximum_event_age_in_seconds = 3600

  # Send failed events to DLQ after retries exhausted
  destination_config {
    on_failure {
      destination = aws_sqs_queue.lambda_dlq.arn
    }
  }
}

# CloudWatch Alarm: Lambda errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "iam-credential-killswitch-errors"
  alarm_description   = "Alert when Lambda function encounters errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.credential_killswitch.function_name
  }

  alarm_actions = [aws_sns_topic.security_alerts.arn]

  tags = {
    Name = "lambda-errors-alarm"
  }
}

# ============================================================================
# EventBridge Rule - Detect AWS Health IAM Credential Exposure Events
# ============================================================================

resource "aws_cloudwatch_event_rule" "health_iam_exposure" {
  name        = "aws-health-iam-credentials-exposed"
  description = "Detect AWS Health events for exposed IAM credentials"

  # Event pattern to match AWS Health IAM credential exposure events
  event_pattern = jsonencode({
    source      = ["aws.health"]
    detail-type = ["AWS Health Event"]
    detail = {
      service = ["IAM"]
      eventTypeCode = ["AWS_RISK_CREDENTIALS_EXPOSED"]
    }
  })

  tags = {
    Name = "aws-health-iam-credentials-exposed"
  }
}

# EventBridge target: Invoke Lambda function
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.health_iam_exposure.name
  target_id = "InvokeCredentialKillswitchLambda"
  arn       = aws_lambda_function.credential_killswitch.arn

  # Add retry policy for target invocation
  retry_policy {
    maximum_event_age_in_seconds = 3600 # 1 hour
    maximum_retry_attempts       = 2
  }

  # Send failed invocations to DLQ
  dead_letter_config {
    arn = aws_sqs_queue.lambda_dlq.arn
  }
}

# Grant EventBridge permission to invoke Lambda
# Security: Scope permission to specific EventBridge rule ARN
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.credential_killswitch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.health_iam_exposure.arn
}

# CloudWatch Alarm: EventBridge rule failures
resource "aws_cloudwatch_metric_alarm" "eventbridge_failures" {
  alarm_name          = "iam-credential-eventbridge-failures"
  alarm_description   = "Alert when EventBridge rule fails to invoke Lambda"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FailedInvocations"
  namespace           = "AWS/Events"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    RuleName = aws_cloudwatch_event_rule.health_iam_exposure.name
  }

  alarm_actions = [aws_sns_topic.security_alerts.arn]

  tags = {
    Name = "eventbridge-failures-alarm"
  }
}
