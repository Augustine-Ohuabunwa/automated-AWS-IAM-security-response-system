"""
Unit tests for IAM Credential Exposure Response Lambda
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

# Set environment variables before importing lambda_function
os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:test-topic'

# Import after setting env vars
import lambda_function


@pytest.fixture
def sample_health_event():
    """Sample AWS Health event for IAM credential exposure"""
    return {
        'version': '0',
        'id': '12345678-1234-1234-1234-123456789012',
        'detail-type': 'AWS Health Event',
        'source': 'aws.health',
        'account': '123456789012',
        'time': '2024-01-15T12:00:00Z',
        'region': 'us-east-1',
        'detail': {
            'eventArn': 'arn:aws:health:us-east-1::event/AWS_RISK_CREDENTIALS_EXPOSED_123',
            'eventTypeCode': 'AWS_RISK_CREDENTIALS_EXPOSED',
            'eventTypeCategory': 'issue',
            'service': 'RISK',
            'affectedEntities': [
                {
                    'entityValue': 'AKIAIOSFODNN7EXAMPLE',
                    'entityArn': 'arn:aws:iam::123456789012:user/test-user'
                }
            ]
        }
    }


@pytest.fixture
def lambda_context():
    """Mock Lambda context object"""
    context = MagicMock()
    context.function_name = 'iam_leaked_credential_killswitch'
    context.function_version = '1'
    context.invoked_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:test'
    context.memory_limit_in_mb = 128
    context.aws_request_id = 'test-request-id'
    context.log_group_name = '/aws/lambda/test'
    context.log_stream_name = 'test-stream'
    return context


class TestLambdaHandler:
    """Tests for the main Lambda handler function"""

    @patch('lambda_function.deactivate_access_key')
    @patch('lambda_function.send_notification')
    def test_handler_success(
        self,
        mock_send_notification,
        mock_deactivate,
        sample_health_event,
        lambda_context
    ):
        """Test successful processing of credential exposure event"""
        # Setup mock
        mock_deactivate.return_value = {
            'accessKeyId': 'AKIAIOSFODNN7EXAMPLE',
            'userName': 'test-user',
            'status': 'deactivated'
        }

        # Execute
        response = lambda_function.lambda_handler(sample_health_event, lambda_context)

        # Verify
        assert response['statusCode'] == 200
        mock_deactivate.assert_called_once_with('AKIAIOSFODNN7EXAMPLE')
        mock_send_notification.assert_called_once()

    def test_handler_wrong_event_type(self, lambda_context):
        """Test handler ignores non-credential-exposure events"""
        event = {
            'detail': {
                'eventTypeCode': 'SOME_OTHER_EVENT',
                'affectedEntities': []
            }
        }

        response = lambda_function.lambda_handler(event, lambda_context)

        assert response['statusCode'] == 200
        assert 'not handled' in response['body']

    @patch('lambda_function.send_error_notification')
    def test_handler_exception(
        self,
        mock_error_notification,
        lambda_context
    ):
        """Test handler error handling"""
        event = {'detail': {}}  # Malformed event

        with pytest.raises(Exception):
            lambda_function.lambda_handler(event, lambda_context)


class TestDeactivateAccessKey:
    """Tests for access key deactivation"""

    @patch('lambda_function.iam_client')
    @patch('lambda_function.find_user_for_access_key')
    def test_deactivate_success(
        self,
        mock_find_user,
        mock_iam_client
    ):
        """Test successful access key deactivation"""
        # Setup mocks
        mock_find_user.return_value = 'test-user'
        mock_iam_client.update_access_key.return_value = {}

        # Execute
        result = lambda_function.deactivate_access_key('AKIAIOSFODNN7EXAMPLE')

        # Verify
        assert result['status'] == 'deactivated'
        assert result['userName'] == 'test-user'
        assert result['accessKeyId'] == 'AKIAIOSFODNN7EXAMPLE'
        mock_iam_client.update_access_key.assert_called_once_with(
            UserName='test-user',
            AccessKeyId='AKIAIOSFODNN7EXAMPLE',
            Status='Inactive'
        )

    @patch('lambda_function.find_user_for_access_key')
    def test_deactivate_key_not_found(self, mock_find_user):
        """Test handling when access key not found"""
        mock_find_user.return_value = ""

        result = lambda_function.deactivate_access_key('AKIAIOSFODNN7EXAMPLE')

        assert result['status'] == 'not_found'
        assert 'Could not find user' in result['message']

    @patch('lambda_function.iam_client')
    @patch('lambda_function.find_user_for_access_key')
    def test_deactivate_api_error(
        self,
        mock_find_user,
        mock_iam_client
    ):
        """Test handling of IAM API errors"""
        mock_find_user.return_value = 'test-user'
        mock_iam_client.update_access_key.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchEntity', 'Message': 'User not found'}},
            'UpdateAccessKey'
        )

        result = lambda_function.deactivate_access_key('AKIAIOSFODNN7EXAMPLE')

        assert result['status'] == 'error'
        assert result['error'] == 'NoSuchEntity'


class TestFindUserForAccessKey:
    """Tests for finding user by access key"""

    @patch('lambda_function.iam_client')
    def test_find_user_success(self, mock_iam_client):
        """Test successfully finding user for access key"""
        # Setup mock paginator
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                'Users': [
                    {'UserName': 'test-user-1'},
                    {'UserName': 'test-user-2'}
                ]
            }
        ]
        mock_iam_client.get_paginator.return_value = mock_paginator

        # Mock list_access_keys responses
        mock_iam_client.list_access_keys.side_effect = [
            {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIAIOSFODNN7WRONG'}
                ]
            },
            {
                'AccessKeyMetadata': [
                    {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE'}
                ]
            }
        ]

        # Execute
        result = lambda_function.find_user_for_access_key('AKIAIOSFODNN7EXAMPLE')

        # Verify
        assert result == 'test-user-2'

    @patch('lambda_function.iam_client')
    def test_find_user_not_found(self, mock_iam_client):
        """Test when access key not found in any user"""
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {'Users': [{'UserName': 'test-user'}]}
        ]
        mock_iam_client.get_paginator.return_value = mock_paginator
        mock_iam_client.list_access_keys.return_value = {
            'AccessKeyMetadata': []
        }

        result = lambda_function.find_user_for_access_key('AKIAIOSFODNN7EXAMPLE')

        assert result == ""


class TestNotifications:
    """Tests for SNS notification functions"""

    @patch('lambda_function.sns_client')
    def test_send_notification_success(self, mock_sns_client):
        """Test successful SNS notification"""
        results = [
            {
                'accessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                'userName': 'test-user',
                'status': 'deactivated',
                'message': 'Access key deactivated'
            }
        ]

        lambda_function.send_notification('AWS_RISK_CREDENTIALS_EXPOSED', results)

        mock_sns_client.publish.assert_called_once()
        call_args = mock_sns_client.publish.call_args
        assert 'SECURITY ALERT' in call_args[1]['Subject']
        assert 'AKIAIOSFODNN7EXAMPLE' in call_args[1]['Message']

    @patch('lambda_function.sns_client')
    def test_send_notification_no_topic_arn(self, mock_sns_client):
        """Test notification skipped when SNS topic not configured"""
        # Temporarily clear SNS_TOPIC_ARN
        original = os.environ.get('SNS_TOPIC_ARN')
        os.environ['SNS_TOPIC_ARN'] = ''

        try:
            lambda_function.send_notification('TEST_EVENT', [])
            mock_sns_client.publish.assert_not_called()
        finally:
            # Restore original value
            if original:
                os.environ['SNS_TOPIC_ARN'] = original

    def test_format_notification_message(self):
        """Test notification message formatting"""
        results = [
            {
                'accessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                'userName': 'test-user',
                'status': 'deactivated',
                'message': 'Successfully deactivated'
            }
        ]

        message = lambda_function.format_notification_message(
            'AWS_RISK_CREDENTIALS_EXPOSED',
            results
        )

        assert 'SECURITY ALERT' in message
        assert 'AKIAIOSFODNN7EXAMPLE' in message
        assert 'test-user' in message
        assert 'deactivated' in message
        assert 'RECOMMENDED ACTIONS' in message
