import unittest
from unittest.mock import MagicMock, patch, call
from .handlers import create_fn
import kopf
import os
import kubernetes.client

class TestHandlers(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.spec = {
            'protocol': 'HTTP',
            'port': 80,
            'vpcId': 'vpc-123',
            'targetType': 'instance',
            'loadBalancerRef': {'name': 'test-lb'},
            'region': 'us-west-2'
        }
        self.spec_with_service = {
            'protocol': 'HTTP',
            'port': 80,
            'vpcId': 'vpc-123',
            'targetType': 'instance',
            'loadBalancerRef': {'name': 'test-lb'},
            'region': 'us-west-2',
            'serviceRef': {'name': 'test-service'}
        }
        self.status = {}
        # Set required environment variable
        os.environ['K8S_CLUSTER_NAME'] = 'test-cluster'

    def tearDown(self):
        # Clean up environment variables
        if 'K8S_CLUSTER_NAME' in os.environ:
            del os.environ['K8S_CLUSTER_NAME']

    def test_create_fn_with_dict_meta(self):
        """Test create_fn with dictionary metadata"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate non-existent target group
            mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
            
            mock_elbv2.create_target_group.return_value = {
                'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
            }
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call create_fn
            result = create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            # Verify finalizer was added via Kubernetes API
            mock_k8s.patch_namespaced_custom_object.assert_called_once_with(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace="default",
                name="test-tg",
                body={
                    'metadata': {
                        'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
                    }
                }
            )
            
            # Verify target group was created with correct name format
            expected_name = f"test-tg-default-test-cluster"
            mock_elbv2.create_target_group.assert_called_once()
            create_args = mock_elbv2.create_target_group.call_args[1]
            self.assertEqual(create_args['Name'], expected_name)
            
            # Verify result
            self.assertEqual(result['targetGroupArn'], 'arn:aws:123')
            self.assertEqual(result['state'], 'active')

    def test_create_fn_existing_target_group(self):
        """Test create_fn when target group already exists"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate existing target group
            mock_elbv2.describe_target_groups.return_value = {
                'TargetGroups': [{
                    'TargetGroupArn': 'arn:aws:existing:123'
                }]
            }
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call create_fn
            result = create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            # Verify finalizer was added via Kubernetes API
            mock_k8s.patch_namespaced_custom_object.assert_called_once_with(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace="default",
                name="test-tg",
                body={
                    'metadata': {
                        'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
                    }
                }
            )
            
            # Verify create_target_group was not called
            mock_elbv2.create_target_group.assert_not_called()
            
            # Verify result uses existing target group ARN
            self.assertEqual(result['targetGroupArn'], 'arn:aws:existing:123')
            self.assertEqual(result['state'], 'active')

    def test_create_fn_missing_cluster_name(self):
        """Test create_fn fails when K8S_CLUSTER_NAME is not set"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        
        # Remove cluster name from environment
        if 'K8S_CLUSTER_NAME' in os.environ:
            del os.environ['K8S_CLUSTER_NAME']
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Verify that create_fn raises an error
            with self.assertRaises(kopf.PermanentError) as context:
                create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            self.assertIn('K8S_CLUSTER_NAME environment variable is required', str(context.exception))
            
            # Verify that no Kubernetes API calls were made
            mock_k8s.patch_namespaced_custom_object.assert_not_called()

    def test_create_fn_with_kopf_meta(self):
        """Test create_fn with kopf.Meta object"""
        class TestMeta:
            def __init__(self):
                self.name = 'test-tg'
                self.namespace = 'default'
                self._dict = {
                    'name': self.name,
                    'namespace': self.namespace,
                    'finalizers': []
                }
            
            def get(self, key, default=None):
                return self._dict.get(key, default)
            
            def to_dict(self):
                return self._dict

        meta = TestMeta()
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate non-existent target group
            mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
            
            mock_elbv2.create_target_group.return_value = {
                'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
            }
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call create_fn
            result = create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            # Verify finalizer was added via Kubernetes API
            mock_k8s.patch_namespaced_custom_object.assert_called_once_with(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace="default",
                name="test-tg",
                body={
                    'metadata': {
                        'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
                    }
                }
            )
            
            # Verify target group was created with correct name format
            expected_name = f"test-tg-default-test-cluster"
            mock_elbv2.create_target_group.assert_called_once()
            create_args = mock_elbv2.create_target_group.call_args[1]
            self.assertEqual(create_args['Name'], expected_name)
            
            # Verify result
            self.assertEqual(result['targetGroupArn'], 'arn:aws:123')
            self.assertEqual(result['state'], 'active')

    def test_create_fn_long_name_validation(self):
        """Test create_fn handles long names correctly by truncating while maintaining format"""
        meta = {
            'name': 'very-long-target-group-name-that-exceeds-limit',
            'namespace': 'very-long-namespace-name',
            'finalizers': []
        }
        
        with patch('controller.handlers.get_elbv2_client') as mock_client:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate non-existent target group
            mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
            
            mock_elbv2.create_target_group.return_value = {
                'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
            }
            
            # Call create_fn
            result = create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            # Get the name used in create_target_group call
            create_args = mock_elbv2.create_target_group.call_args[1]
            generated_name = create_args['Name']
            
            # Verify name length is within limit
            self.assertLessEqual(len(generated_name), 32)
            
            # Verify name format is maintained (name-namespace-cluster)
            parts = generated_name.split('-')
            self.assertEqual(len(parts), 3)  # Should still have 3 parts
            
            # Verify each part is present (though truncated)
            self.assertTrue(parts[0] in meta['name'])  # First part should be from name
            self.assertTrue(parts[1] in meta['namespace'])  # Second part should be from namespace
            self.assertEqual(parts[2], 'test-cluster'[:8])  # Last part should be from cluster name
            
            # Verify result
            self.assertEqual(result['targetGroupArn'], 'arn:aws:123')
            self.assertEqual(result['state'], 'active')

    def test_create_fn_with_object_meta(self):
        """Test create_fn with an object that has required attributes but no to_dict method"""
        class SimpleMeta:
            def __init__(self):
                self.name = 'test-tg'
                self.namespace = 'default'
                self.finalizers = []
                self.annotations = {}

            def get(self, key, default=None):
                return getattr(self, key, default)

        meta = SimpleMeta()
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate non-existent target group
            mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
            
            mock_elbv2.create_target_group.return_value = {
                'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
            }
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call create_fn
            result = create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            # Verify finalizer was added via Kubernetes API
            mock_k8s.patch_namespaced_custom_object.assert_called_once_with(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace="default",
                name="test-tg",
                body={
                    'metadata': {
                        'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
                    }
                }
            )
            
            # Verify target group was created with correct name format
            expected_name = f"test-tg-default-test-cluster"
            mock_elbv2.create_target_group.assert_called_once()
            create_args = mock_elbv2.create_target_group.call_args[1]
            self.assertEqual(create_args['Name'], expected_name)
            
            # Verify result
            self.assertEqual(result['targetGroupArn'], 'arn:aws:123')
            self.assertEqual(result['state'], 'active')

    def test_create_fn_edge_case_name_lengths(self):
        """Test create_fn handles edge cases with various name lengths"""
        test_cases = [
            {
                'name': 'x',  # Very short name
                'namespace': 'default',
                'expected_format': True
            },
            {
                'name': 'a' * 50,  # Very long name
                'namespace': 'b' * 50,
                'expected_format': True
            },
            {
                'name': 'test-name',
                'namespace': 'c' * 50,  # Very long namespace
                'expected_format': True
            }
        ]
        
        for case in test_cases:
            meta = {
                'name': case['name'],
                'namespace': case['namespace'],
                'finalizers': []
            }
            
            with patch('controller.handlers.get_elbv2_client') as mock_client, \
                 patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
                mock_elbv2 = MagicMock()
                mock_client.return_value = mock_elbv2
                mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
                mock_elbv2.create_target_group.return_value = {
                    'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
                }
                
                # Mock Kubernetes API
                mock_k8s = MagicMock()
                mock_k8s_api.return_value = mock_k8s
                
                # Call create_fn
                create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
                
                # Verify finalizer was added via Kubernetes API
                mock_k8s.patch_namespaced_custom_object.assert_called_once_with(
                    group="aws.k8s.io",
                    version="v1",
                    plural="awstargetgroups",
                    namespace=case['namespace'],
                    name=case['name'],
                    body={
                        'metadata': {
                            'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
                        }
                    }
                )
                
                # Get generated name
                create_args = mock_elbv2.create_target_group.call_args[1]
                generated_name = create_args['Name']
                
                # Verify constraints
                self.assertLessEqual(len(generated_name), 32)  # Length constraint
                parts = generated_name.split('-')
                self.assertEqual(len(parts), 3)  # Format constraint
                self.assertTrue(parts[0] in case['name'])  # Name part present
                self.assertTrue(parts[1] in case['namespace'])  # Namespace part present
                self.assertTrue(parts[2] in 'test-cluster')  # Cluster part present

    def test_create_fn_updates_status(self):
        """Test that create_fn properly updates the resource status"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate non-existent target group
            mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
            
            mock_elbv2.create_target_group.return_value = {
                'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
            }
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call create_fn
            result = create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            # Verify status was updated using the status subresource
            mock_k8s.patch_namespaced_custom_object_status.assert_called_once_with(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace="default",
                name="test-tg",
                body={'status': {
                    'targetGroupArn': 'arn:aws:123',
                    'state': 'active',
                    'ruleArn': None,
                    'error': None
                }}
            )
            
            # Verify result contains all expected fields
            self.assertEqual(result['targetGroupArn'], 'arn:aws:123')
            self.assertEqual(result['state'], 'active')
            self.assertIsNone(result['ruleArn'])
            self.assertIsNone(result.get('error'))

    def test_create_fn_updates_status_on_error(self):
        """Test that create_fn updates status on error"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to raise an error
            mock_elbv2.describe_target_groups.side_effect = Exception("Test error")
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call create_fn and expect it to raise an error
            with self.assertRaises(kopf.PermanentError):
                create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            # Verify error status was updated
            mock_k8s.patch_namespaced_custom_object_status.assert_called_once_with(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace="default",
                name="test-tg",
                body={'status': {
                    'state': 'error',
                    'error': 'Test error'
                }}
            )

    def test_spec_handler_updates_status(self):
        """Test that spec_handler properly updates the resource status"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        status = {'targetGroupArn': 'arn:aws:123'}
        old_spec = self.spec.copy()
        new_spec = self.spec.copy()
        new_spec['port'] = 8080  # Change port to trigger update
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock reconcile_target_group to indicate changes were made
            with patch('controller.handlers.reconcile_target_group') as mock_reconcile:
                mock_reconcile.return_value = True
                
                # Mock Kubernetes API
                mock_k8s = MagicMock()
                mock_k8s_api.return_value = mock_k8s
                
                # Call spec_handler
                spec_handler(spec=new_spec, meta=meta, status=status, old=old_spec, new=new_spec, logger=self.logger)
                
                # Verify status was updated using the status subresource
                mock_k8s.patch_namespaced_custom_object_status.assert_called_once_with(
                    group="aws.k8s.io",
                    version="v1",
                    plural="awstargetgroups",
                    namespace="default",
                    name="test-tg",
                    body={'status': {
                        'targetGroupArn': 'arn:aws:123',
                        'state': 'active',
                        'ruleArn': None,
                        'error': None
                    }}
                )

    def test_delete_fn_with_cleanup(self):
        """Test delete_fn with successful cleanup of rules and target group"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
        }
        status = {'targetGroupArn': 'arn:aws:123'}
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api, \
             patch('controller.aws.listener.cleanup_target_group_rules') as mock_cleanup:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call delete_fn
            delete_fn(spec=self.spec, meta=meta, status=status, logger=self.logger)
            
            # Verify cleanup was called
            mock_cleanup.assert_called_once_with(mock_elbv2, 'arn:aws:123', region='us-west-2')
            
            # Verify target group was deleted
            mock_elbv2.delete_target_group.assert_called_once_with(
                TargetGroupArn='arn:aws:123'
            )

    def test_delete_fn_handles_resource_in_use(self):
        """Test delete_fn handles ResourceInUse error by raising TemporaryError"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
        }
        status = {'targetGroupArn': 'arn:aws:123'}
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api, \
             patch('controller.aws.listener.cleanup_target_group_rules') as mock_cleanup:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock delete_target_group to fail with ResourceInUse
            mock_elbv2.delete_target_group.side_effect = mock_elbv2.exceptions.ResourceInUseException({
                'Error': {
                    'Code': 'ResourceInUse',
                    'Message': 'Target group is currently in use'
                }
            }, 'DeleteTargetGroup')
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call delete_fn and expect TemporaryError
            with self.assertRaises(kopf.TemporaryError) as context:
                delete_fn(spec=self.spec, meta=meta, status=status, logger=self.logger)
            
            # Verify error message
            self.assertIn('Target group is still in use', str(context.exception))
            
            # Verify cleanup was called
            mock_cleanup.assert_called_once_with(mock_elbv2, 'arn:aws:123', region='us-west-2')

    def test_delete_fn_handles_cleanup_error(self):
        """Test delete_fn handles errors during cleanup"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
        }
        status = {'targetGroupArn': 'arn:aws:123'}
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api, \
             patch('controller.aws.listener.cleanup_target_group_rules') as mock_cleanup:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock cleanup to fail
            mock_cleanup.side_effect = kopf.PermanentError('Failed to cleanup rules')
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call delete_fn and expect PermanentError
            with self.assertRaises(kopf.PermanentError) as context:
                delete_fn(spec=self.spec, meta=meta, status=status, logger=self.logger)
            
            # Verify error message
            self.assertIn('Failed to cleanup rules', str(context.exception))
            
            # Verify target group was not deleted
            mock_elbv2.delete_target_group.assert_not_called()

    def test_delete_fn_handles_missing_target_group(self):
        """Test delete_fn handles case where target group ARN is missing from status"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': ['aws.k8s.io/awstargetgroup-finalizer']
        }
        status = {}  # No targetGroupArn
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api, \
             patch('controller.aws.listener.cleanup_target_group_rules') as mock_cleanup:
            # Mock AWS responses
    def test_create_fn_creates_targetgroupbinding(self):
        """Test that create_fn creates a TargetGroupBinding when serviceRef is specified"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate non-existent target group
            mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
            
            mock_elbv2.create_target_group.return_value = {
                'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
            }
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call create_fn with spec that includes serviceRef
            result = create_fn(spec=self.spec_with_service, meta=meta, status=self.status, logger=self.logger)
            
            # Verify TargetGroupBinding was created
            mock_k8s.create_namespaced_custom_object.assert_called_with(
                group="aws.k8s.io",
                version="v1",
                plural="targetgroupbindings",
                namespace="default",
                body={
                    'apiVersion': 'aws.k8s.io/v1',
                    'kind': 'TargetGroupBinding',
                    'metadata': {
                        'name': 'test-tg-binding',
                        'namespace': 'default',
                        'labels': {
                            'created-by': 'aws-targetgroup-operator',
                            'targetgroup-name': 'test-tg'
                        }
                    },
                    'spec': {
                        'targetGroupARN': 'arn:aws:123',
                        'serviceRef': {
                            'name': 'test-service',
                            'port': 80
                        }
                    }
                }
            )
            
            # Verify result
            self.assertEqual(result['targetGroupArn'], 'arn:aws:123')
            self.assertEqual(result['state'], 'active')

    def test_create_fn_handles_existing_targetgroupbinding(self):
        """Test that create_fn handles case where TargetGroupBinding already exists"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate non-existent target group
            mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
            
            mock_elbv2.create_target_group.return_value = {
                'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
            }
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Mock create_namespaced_custom_object to raise Conflict error
            mock_k8s.create_namespaced_custom_object.side_effect = kubernetes.client.rest.ApiException(status=409)
            
            # Call create_fn with spec that includes serviceRef
            result = create_fn(spec=self.spec_with_service, meta=meta, status=self.status, logger=self.logger)
            
            # Verify TargetGroupBinding creation was attempted
            mock_k8s.create_namespaced_custom_object.assert_called_once()
            
            # Verify result is still successful
            self.assertEqual(result['targetGroupArn'], 'arn:aws:123')
            self.assertEqual(result['state'], 'active')

    def test_create_fn_skips_targetgroupbinding_without_serviceref(self):
        """Test that create_fn skips TargetGroupBinding creation when serviceRef is not specified"""
        meta = {
            'name': 'test-tg',
            'namespace': 'default',
            'finalizers': []
        }
        
        with patch('controller.handlers.get_elbv2_client') as mock_client, \
             patch('kubernetes.client.CustomObjectsApi') as mock_k8s_api:
            # Mock AWS responses
            mock_elbv2 = MagicMock()
            mock_client.return_value = mock_elbv2
            
            # Mock describe_target_groups to simulate non-existent target group
            mock_elbv2.describe_target_groups.side_effect = mock_elbv2.exceptions.TargetGroupNotFoundException({}, '')
            
            mock_elbv2.create_target_group.return_value = {
                'TargetGroups': [{'TargetGroupArn': 'arn:aws:123'}]
            }
            
            # Mock Kubernetes API
            mock_k8s = MagicMock()
            mock_k8s_api.return_value = mock_k8s
            
            # Call create_fn with spec that does not include serviceRef
            result = create_fn(spec=self.spec, meta=meta, status=self.status, logger=self.logger)
            
            # Verify no TargetGroupBinding was created
            create_calls = [call for call in mock_k8s.create_namespaced_custom_object.mock_calls 
                          if call[2].get('plural') == 'targetgroupbindings']
            self.assertEqual(len(create_calls), 0)
            
            # Verify result
            self.assertEqual(result['targetGroupArn'], 'arn:aws:123')
            self.assertEqual(result['state'], 'active')

if __name__ == '__main__':
    unittest.main()