"""
AWS IAM Credential Exposure Response Lambda
Automatically responds to AWS Health events indicating compromised IAM credentials
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for IAM credential exposure events

    Args:
        event: AWS Health event containing credential exposure details
        context: Lambda context object

    Returns:
        Response dictionary with status and details
    """
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # Extract event details
        detail = event.get('detail', {})
        event_type_code = detail.get('eventTypeCode', '')
        affected_entities = detail.get('affectedEntities', [])

        # Validate this is an IAM credential exposure event
        if 'AWS_RISK_CREDENTIALS_EXPOSED' not in event_type_code:
            logger.warning(f"Unexpected event type: {event_type_code}")
            return {
                'statusCode': 200,
                'body': json.dumps('Event type not handled by this function')
            }

        # Process each affected entity
        results = []
        for entity in affected_entities:
            entity_value = entity.get('entityValue')
            logger.info(f"Processing affected entity: {entity_value}")

            # Identify if it's an access key or IAM user
            if entity_value and entity_value.startswith('AKIA'):
                # It's an access key ID
                result = deactivate_access_key(entity_value)
                results.append(result)
            else:
                logger.warning(f"Unknown entity format: {entity_value}")

        # Send notification
        send_notification(event_type_code, results)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully processed credential exposure event',
                'results': results
            })
        }

    except Exception as e:
        logger.error(f"Error processing event: {str(e)}", exc_info=True)
        send_error_notification(str(e), event)
        raise


def deactivate_access_key(access_key_id: str) -> Dict[str, Any]:
    """
    Deactivate a compromised IAM access key

    Args:
        access_key_id: The AWS access key ID to deactivate

    Returns:
        Dictionary with deactivation status and details
    """
    try:
        # First, find which user owns this access key
        user_name = find_user_for_access_key(access_key_id)

        if not user_name:
            return {
                'accessKeyId': access_key_id,
                'status': 'not_found',
                'message': 'Could not find user for this access key'
            }

        # Deactivate the access key
        iam_client.update_access_key(
            UserName=user_name,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )

        logger.info(f"Successfully deactivated access key {access_key_id} for user {user_name}")

        return {
            'accessKeyId': access_key_id,
            'userName': user_name,
            'status': 'deactivated',
            'timestamp': datetime.utcnow().isoformat(),
            'message': f'Access key deactivated for user {user_name}'
        }

    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(f"AWS API error deactivating key {access_key_id}: {error_code}")
        return {
            'accessKeyId': access_key_id,
            'status': 'error',
            'error': error_code,
            'message': str(e)
        }


def find_user_for_access_key(access_key_id: str) -> str:
    """
    Find the IAM user that owns a specific access key

    Args:
        access_key_id: The access key ID to search for

    Returns:
        IAM username or empty string if not found
    """
    try:
        # List all users
        paginator = iam_client.get_paginator('list_users')

        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']

                # List access keys for this user
                keys_response = iam_client.list_access_keys(UserName=user_name)

                for key in keys_response['AccessKeyMetadata']:
                    if key['AccessKeyId'] == access_key_id:
                        return user_name

        logger.warning(f"Access key {access_key_id} not found in any user")
        return ""

    except ClientError as e:
        logger.error(f"Error finding user for access key: {str(e)}")
        return ""


def send_notification(event_type: str, results: list) -> None:
    """
    Send SNS notification about the remediation action

    Args:
        event_type: Type of security event
        results: List of remediation results
    """
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not configured, skipping notification")
        return

    try:
        message = format_notification_message(event_type, results)

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='[SECURITY ALERT] IAM Credentials Exposed - Automatic Response Taken',
            Message=message
        )

        logger.info("Notification sent successfully")

    except ClientError as e:
        logger.error(f"Error sending SNS notification: {str(e)}")


def send_error_notification(error_message: str, event: Dict[str, Any]) -> None:
    """
    Send error notification when Lambda encounters an exception

    Args:
        error_message: The error message
        event: Original event that caused the error
    """
    if not SNS_TOPIC_ARN:
        return

    try:
        message = f"""
LAMBDA EXECUTION ERROR

An error occurred while processing IAM credential exposure event.

Error: {error_message}

Event Details:
{json.dumps(event, indent=2, default=str)}

Please investigate immediately.
"""

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='[ERROR] IAM Credential Response Lambda Failed',
            Message=message
        )

    except Exception as e:
        logger.error(f"Failed to send error notification: {str(e)}")


def format_notification_message(event_type: str, results: list) -> str:
    """
    Format a human-readable notification message

    Args:
        event_type: Type of security event
        results: List of remediation results

    Returns:
        Formatted message string
    """
    message_lines = [
        "SECURITY ALERT: IAM Credentials Exposed",
        "=" * 60,
        f"Event Type: {event_type}",
        f"Timestamp: {datetime.utcnow().isoformat()}",
        "",
        "AUTOMATIC RESPONSE TAKEN:",
        ""
    ]

    for idx, result in enumerate(results, 1):
        message_lines.append(f"{idx}. Access Key: {result.get('accessKeyId', 'Unknown')}")
        message_lines.append(f"   Status: {result.get('status', 'Unknown')}")
        message_lines.append(f"   User: {result.get('userName', 'Unknown')}")
        message_lines.append(f"   Message: {result.get('message', 'No details')}")
        message_lines.append("")

    message_lines.extend([
        "=" * 60,
        "RECOMMENDED ACTIONS:",
        "1. Review CloudWatch Logs for this Lambda function",
        "2. Investigate how the credentials were exposed",
        "3. Create new access keys for affected users if needed",
        "4. Review recent API activity for suspicious actions",
        "5. Consider enabling additional security controls",
        "",
        "This is an automated response system.",
        "Manual review and follow-up actions are required."
    ])

    return "\n".join(message_lines)
