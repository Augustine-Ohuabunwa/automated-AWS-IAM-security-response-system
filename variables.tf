variable "aws_region" {
  description = "AWS region for deployment (us-east-1 recommended for AWS Health events without determined regions)"
  type        = string
  default     = "us-east-1"
}

variable "security_notification_email" {
  description = "Email address for security team notifications when IAM credentials are exposed"
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.security_notification_email))
    error_message = "Must be a valid email address"
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days (minimum 30 for security events, recommend 90)"
  type        = number
  default     = 90
  validation {
    condition     = var.log_retention_days >= 30
    error_message = "Security event logs should be retained for at least 30 days"
  }
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds (recommend 60-120 for API calls + potential CloudTrail queries)"
  type        = number
  default     = 120
  validation {
    condition     = var.lambda_timeout >= 60 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 60 and 900 seconds"
  }
}

variable "lambda_memory_size" {
  description = "Lambda function memory allocation in MB (affects CPU allocation)"
  type        = number
  default     = 256
  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory must be between 128 and 10240 MB"
  }
}

variable "environment" {
  description = "Environment designation for resource tagging"
  type        = string
  default     = "Production"
}

variable "dlq_retention_days" {
  description = "Dead Letter Queue message retention period in days"
  type        = number
  default     = 14
  validation {
    condition     = var.dlq_retention_days >= 1 && var.dlq_retention_days <= 14
    error_message = "SQS retention must be between 1 and 14 days"
  }
}
