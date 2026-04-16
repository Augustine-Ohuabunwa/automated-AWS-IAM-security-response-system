# AWS IAM Credential Exposure Response System

Production-grade automated security response system that detects and immediately disables exposed IAM credentials using AWS Health events, EventBridge, and Lambda.

## Architecture Overview

This infrastructure implements a fully automated security response pipeline:

1. **AWS Health** detects exposed IAM credentials in public code repositories
2. **EventBridge** captures the AWS_RISK_CREDENTIALS_EXPOSED event
3. **Lambda** automatically disables affected access keys (preserves for forensics)
4. **SNS** notifies security team with detailed action report
5. **SQS DLQ** captures any Lambda failures for investigation
6. **CloudWatch Alarms** monitor system health and alert on issues

## Key Features

- **Automatic Response**: Zero-touch credential disablement within seconds of detection
- **Idempotent Execution**: Safely handles duplicate AWS Health events
- **Least Privilege IAM**: All policies scoped to specific resources where possible
- **Comprehensive Monitoring**: CloudWatch alarms for Lambda errors, DLQ depth, and EventBridge failures
- **Forensic Preservation**: Disables keys instead of deleting them for investigation
- **Structured Logging**: JSON-formatted logs for easy querying and analysis
- **Production Hardening**: Encryption at rest, retry policies, proper error handling

## Security Best Practices Implemented

- ✓ Principle of least privilege for all IAM policies
- ✓ Encryption at rest for SNS and SQS (AWS managed keys)
- ✓ Resource-scoped IAM policies (CloudWatch Logs, SNS, SQS)
- ✓ Lambda async invocation retry policy (2 retries, 1-hour max age)
- ✓ Dead letter queue for failure tracking
- ✓ CloudWatch alarms for operational monitoring
- ✓ Comprehensive resource tagging
- ✓ Structured JSON logging for audit trail
- ✓ Idempotent operation handling

## Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.0
- AWS account with permissions to create IAM roles, Lambda functions, EventBridge rules, SNS topics, and SQS queues

## Quick Start

### 1. Configure Variables

Copy the example configuration and customize:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set your security team email:

```hcl
security_notification_email = "security-team@yourcompany.com"
```

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review Deployment Plan

```bash
terraform plan
```

Review the resources that will be created:
- Lambda function with IAM role and policies
- EventBridge rule and target
- SNS topic and email subscription
- SQS Dead Letter Queue
- CloudWatch Log Group
- CloudWatch Alarms (3 total)

### 4. Deploy Infrastructure

```bash
terraform apply
```

Type `yes` to confirm deployment.

### 5. Confirm SNS Subscription

Check the email inbox for `security_notification_email` and confirm the SNS subscription by clicking the confirmation link.

## Configuration Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `security_notification_email` | Email for security alerts | - | Yes |
| `aws_region` | AWS region for deployment | `us-east-1` | No |
| `log_retention_days` | CloudWatch Logs retention | `90` | No |
| `lambda_timeout` | Lambda timeout in seconds | `120` | No |
| `lambda_memory_size` | Lambda memory in MB | `256` | No |
| `environment` | Environment tag | `Production` | No |
| `dlq_retention_days` | DLQ retention in days | `14` | No |

## Outputs

After deployment, Terraform outputs important resource identifiers:

- `sns_topic_arn`: ARN for security alert topic
- `lambda_function_name`: Name of the credential killswitch function
- `lambda_function_arn`: ARN of the Lambda function
- `eventbridge_rule_name`: Name of the Health event detection rule
- `dlq_url`: URL of the Dead Letter Queue
- `cloudwatch_log_group_name`: Name of the Lambda log group

## Testing the System

### Simulate an AWS Health Event

AWS Health events cannot be easily simulated, but you can test the Lambda function directly:

1. Create a test event file `test-event.json`:

```json
{
  "version": "0",
  "id": "test-event-123",
  "detail-type": "AWS Health Event",
  "source": "aws.health",
  "account": "123456789012",
  "time": "2026-04-16T10:00:00Z",
  "region": "us-east-1",
  "resources": [],
  "detail": {
    "eventArn": "arn:aws:health:us-east-1::event/IAM/AWS_RISK_CREDENTIALS_EXPOSED/test-123",
    "service": "IAM",
    "eventTypeCode": "AWS_RISK_CREDENTIALS_EXPOSED",
    "affectedEntities": [
      {
        "entityValue": "arn:aws:iam::123456789012:user/test-user"
      }
    ]
  }
}
```

2. Invoke the Lambda function:

```bash
aws lambda invoke \
  --function-name iam_leaked_credential_killswitch \
  --payload file://test-event.json \
  --region us-east-1 \
  response.json
```

3. Check the response:

```bash
cat response.json
```

4. Verify CloudWatch Logs:

```bash
aws logs tail /aws/lambda/iam_leaked_credential_killswitch --follow
```

IMPORTANT: Replace `test-user` with an actual IAM user in your account that has access keys you're willing to disable for testing.

## Operational Monitoring

### CloudWatch Alarms

Three CloudWatch alarms monitor system health:

1. **iam-credential-killswitch-errors**: Lambda function errors
2. **iam-credential-dlq-messages-detected**: Messages in DLQ (indicates failures)
3. **iam-credential-eventbridge-failures**: EventBridge invocation failures

All alarms send notifications to the security alerts SNS topic.

### CloudWatch Logs

View Lambda execution logs:

```bash
aws logs tail /aws/lambda/iam_leaked_credential_killswitch --follow --format short
```

Query logs for specific events:

```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/iam_leaked_credential_killswitch \
  --filter-pattern '{ $.message = "Successfully disabled access key" }'
```

### Dead Letter Queue Monitoring

Check for failed invocations:

```bash
aws sqs get-queue-attributes \
  --queue-url $(terraform output -raw dlq_url) \
  --attribute-names ApproximateNumberOfMessages
```

If messages appear in the DLQ, retrieve and investigate:

```bash
aws sqs receive-message \
  --queue-url $(terraform output -raw dlq_url) \
  --max-number-of-messages 10
```

## How It Works

### Event Flow

1. **Detection**: AWS Health monitors public code repositories for exposed IAM credentials
2. **Event Emission**: AWS Health emits `AWS_RISK_CREDENTIALS_EXPOSED` event to EventBridge
3. **Rule Match**: EventBridge rule filters for IAM credential exposure events
4. **Lambda Invocation**: EventBridge invokes Lambda function asynchronously
5. **Credential Disablement**: Lambda lists and disables all active access keys for affected user
6. **Notification**: Lambda sends detailed report to SNS topic
7. **Monitoring**: CloudWatch alarms track execution and DLQ for failures

### Lambda Function Logic

The Python handler implements:

1. **Event Parsing**: Extracts affected IAM users from AWS Health event
2. **Idempotency Check**: Verifies if access keys are already inactive
3. **Key Disablement**: Calls `iam:UpdateAccessKey` to disable (not delete) keys
4. **Structured Logging**: JSON logs for each action taken
5. **SNS Notification**: Detailed report including user, keys, actions, and timestamp
6. **Error Handling**: Comprehensive try/except blocks with SNS error notifications

### IAM Permissions Model

Lambda execution role has four scoped policies:

1. **CloudWatch Logs**: Write logs to function's specific log group
2. **IAM Access**: List and update access keys for IAM users
3. **SNS Publish**: Send notifications to specific security alert topic
4. **SQS Send**: Write failed events to specific DLQ

NOTE: IAM actions cannot be scoped to specific users in the resource ARN due to AWS IAM limitations, but policies include conditions where possible to limit blast radius.

## Cost Estimation

Estimated monthly cost (assuming 10 exposed credential events per month):

- **Lambda**: ~0.02 USD (10 invocations, 2 second average duration)
- **EventBridge**: ~0.00 USD (first 100M events free)
- **SNS**: ~0.00 USD (first 1,000 email notifications free)
- **SQS**: ~0.00 USD (minimal DLQ usage)
- **CloudWatch Logs**: ~1.00 USD (10 GB storage, 90 days retention)

**Total**: ~1.02 USD per month

NOTE: Costs may vary based on actual event volume and log verbosity.

## Security Incident Response

When an AWS Health credential exposure event occurs:

### Immediate Response (Automated)

1. Lambda automatically disables all access keys for affected user
2. SNS email sent to security team within seconds
3. All actions logged to CloudWatch with structured JSON

### Manual Follow-Up Steps

1. **Review CloudWatch Logs** for detailed execution trace
2. **Query CloudTrail** for unauthorized API calls:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=Username,AttributeValue=<affected-user> \
     --start-time <24-hours-ago> \
     --max-results 50
   ```
3. **Contact Affected User** to rotate credentials and review security practices
4. **Investigate Exposure Source** (public GitHub repo, pastebin, etc.)
5. **Assess Blast Radius** from CloudTrail logs
6. **Document Incident** following your organization's incident response procedures

## Cleanup / Destruction

To remove all infrastructure:

```bash
terraform destroy
```

WARNING: This will delete all resources including CloudWatch Logs. Ensure logs are exported if needed for compliance.

## Troubleshooting

### SNS Subscription Not Confirmed

**Symptom**: No email notifications received
**Solution**: Check spam folder for AWS SNS confirmation email, or check SNS subscription status:

```bash
aws sns list-subscriptions-by-topic --topic-arn $(terraform output -raw sns_topic_arn)
```

### Lambda Execution Errors

**Symptom**: CloudWatch alarm for Lambda errors
**Solution**: Check CloudWatch Logs for detailed error messages:

```bash
aws logs tail /aws/lambda/iam_leaked_credential_killswitch --follow
```

### EventBridge Rule Not Triggering

**Symptom**: No Lambda invocations despite AWS Health events
**Solution**: Verify EventBridge rule is enabled:

```bash
aws events describe-rule --name aws-health-iam-credentials-exposed
```

### IAM Permission Denied Errors

**Symptom**: Lambda cannot list or update access keys
**Solution**: Verify Lambda execution role has correct policies attached:

```bash
aws iam get-role --role-name iam-credential-killswitch-lambda-role
aws iam list-role-policies --role-name iam-credential-killswitch-lambda-role
```

## References

- [AWS Health Tools - Credential Exposure Response](https://github.com/aws/aws-health-tools/blob/master/automated-actions/AWS_RISK_CREDENTIALS_EXPOSED/README.md)
- [AWS Lambda Error Handling Patterns](https://aws.amazon.com/blogs/compute/implementing-aws-lambda-error-handling-patterns/)
- [AWS Health Security Best Practices](https://docs.aws.amazon.com/health/latest/ug/security-best-practices.html)
- [EventBridge Event Pattern Reference](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

## License

This infrastructure code is provided as-is for production use. Review and customize according to your organization's security policies and compliance requirements.

## Support

For issues or questions:
1. Review CloudWatch Logs for detailed execution traces
2. Check CloudWatch Alarms for system health status
3. Examine DLQ for failed invocations
4. Consult AWS Health Tools repository for reference implementations
