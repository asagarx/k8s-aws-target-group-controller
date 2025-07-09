import unittest
from unittest.mock import MagicMock, patch
import os
from .client import get_credentials, get_elbv2_client

class TestAWSClient(unittest.TestCase):
    def setUp(self):
        # Clear any cached clients
        get_elbv2_client.cache_clear()
        
    def test_get_credentials_irsa(self):
        """Test that IRSA credentials are properly detected and used"""
        mock_session = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = "MOCK_ACCESS_KEY"
        mock_credentials.secret_key = "MOCK_SECRET_KEY"
        mock_credentials.token = "MOCK_TOKEN"
        mock_session.get_credentials.return_value = mock_credentials
        
        with patch('boto3.Session', return_value=mock_session):
            credentials = get_credentials()
            self.assertIsNotNone(credentials)
            self.assertEqual(credentials.access_key, "MOCK_ACCESS_KEY")
            self.assertEqual(credentials.secret_key, "MOCK_SECRET_KEY")
            self.assertEqual(credentials.token, "MOCK_TOKEN")
    
    def test_get_credentials_none(self):
        """Test handling when no credentials are found"""
        mock_session = MagicMock()
        mock_session.get_credentials.return_value = None
        
        with patch('boto3.Session', return_value=mock_session):
            credentials = get_credentials()
            self.assertIsNone(credentials)
    
    def test_get_elbv2_client_with_region(self):
        """Test client creation with explicit region"""
        mock_session = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = "MOCK_ACCESS_KEY"
        mock_credentials.secret_key = "MOCK_SECRET_KEY"
        mock_credentials.token = "MOCK_TOKEN"
        mock_session.get_credentials.return_value = mock_credentials
        
        with patch('boto3.Session', return_value=mock_session), \
             patch('boto3.client') as mock_client:
            client = get_elbv2_client(region="us-west-2")
            mock_client.assert_called_once()
            call_kwargs = mock_client.call_args[1]
            self.assertEqual(call_kwargs['region_name'], "us-west-2")
            self.assertEqual(call_kwargs['aws_access_key_id'], "MOCK_ACCESS_KEY")
            self.assertEqual(call_kwargs['aws_secret_access_key'], "MOCK_SECRET_KEY")
            self.assertEqual(call_kwargs['aws_session_token'], "MOCK_TOKEN")
    
    def test_get_elbv2_client_default_region(self):
        """Test client creation with region from environment"""
        mock_session = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = "MOCK_ACCESS_KEY"
        mock_credentials.secret_key = "MOCK_SECRET_KEY"
        mock_credentials.token = None
        mock_session.get_credentials.return_value = mock_credentials
        
        with patch('boto3.Session', return_value=mock_session), \
             patch('boto3.client') as mock_client, \
             patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'}):
            client = get_elbv2_client()
            mock_client.assert_called_once()
            call_kwargs = mock_client.call_args[1]
            self.assertEqual(call_kwargs['region_name'], "us-east-1")
            self.assertEqual(call_kwargs['aws_access_key_id'], "MOCK_ACCESS_KEY")
            self.assertEqual(call_kwargs['aws_secret_access_key'], "MOCK_SECRET_KEY")
            self.assertNotIn('aws_session_token', call_kwargs)
            # Verify STS regional endpoints are configured
            self.assertEqual(os.environ.get('AWS_STS_REGIONAL_ENDPOINTS'), 'regional')

    def test_sts_regional_endpoints_not_set_without_region(self):
        """Test that STS regional endpoints are not configured without a region"""
        mock_session = MagicMock()
        mock_credentials = MagicMock()
        mock_session.get_credentials.return_value = mock_credentials
        
        with patch('boto3.Session', return_value=mock_session), \
             patch('boto3.client') as mock_client, \
             patch.dict(os.environ, {}, clear=True):
            client = get_elbv2_client()
            self.assertNotIn('AWS_STS_REGIONAL_ENDPOINTS', os.environ)

if __name__ == '__main__':
    unittest.main()