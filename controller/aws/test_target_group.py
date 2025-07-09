import unittest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
import kopf
from .target_group import process_target_group_annotations

class TestTargetGroup(unittest.TestCase):
    def setUp(self):
        self.mock_elbv2 = MagicMock()
        self.target_group_arn = "arn:aws:elasticloadbalancing:region:account:targetgroup/test/123"

    def test_process_health_check_annotations(self):
        annotations = {
            "aws.k8s.io.targetGroup/healthCheck.enabled": "true",
            "aws.k8s.io.targetGroup/healthCheck.healthyThresholdCount": "3",
            "aws.k8s.io.targetGroup/healthCheck.unhealthyThresholdCount": "2",
            "aws.k8s.io.targetGroup/healthCheck.HealthCheckIntervalSeconds": "30",
            "aws.k8s.io.targetGroup/healthCheck.HealthCheckTimeoutSeconds": "5",
            "aws.k8s.io.targetGroup/healthCheck.path": "/health",
            "aws.k8s.io.targetGroup/healthCheck.port": "traffic-port",
            "aws.k8s.io.targetGroup/healthCheck.protocol": "HTTP"
        }

        changes_made = process_target_group_annotations(self.mock_elbv2, self.target_group_arn, annotations)
        
        self.assertTrue(changes_made)
        self.mock_elbv2.modify_target_group.assert_called_once()
        call_args = self.mock_elbv2.modify_target_group.call_args[1]
        self.assertEqual(call_args["TargetGroupArn"], self.target_group_arn)
        self.assertEqual(call_args["HealthyThresholdCount"], 3)
        self.assertEqual(call_args["UnhealthyThresholdCount"], 2)
        self.assertEqual(call_args["HealthCheckIntervalSeconds"], 30)
        self.assertEqual(call_args["HealthCheckTimeoutSeconds"], 5)
        self.assertEqual(call_args["HealthCheckPath"], "/health")
        self.assertEqual(call_args["HealthCheckPort"], "traffic-port")
        self.assertEqual(call_args["HealthCheckProtocol"], "HTTP")
        self.assertEqual(call_args["HealthCheckEnabled"], True)

    def test_process_attributes_annotations(self):
        annotations = {
            "aws.k8s.io.targetGroup/attribute.deregistration_delay.timeout_seconds": "300",
            "aws.k8s.io.targetGroup/attribute.stickiness.enabled": "true",
            "aws.k8s.io.targetGroup/attribute.stickiness.type": "lb_cookie",
            "aws.k8s.io.targetGroup/attribute.stickiness.lb_cookie.duration_seconds": "86400"
        }

        changes_made = process_target_group_annotations(self.mock_elbv2, self.target_group_arn, annotations)
        
        self.assertTrue(changes_made)
        self.mock_elbv2.modify_target_group_attributes.assert_called_once()
        call_args = self.mock_elbv2.modify_target_group_attributes.call_args[1]
        self.assertEqual(call_args["TargetGroupArn"], self.target_group_arn)
        
        attributes = call_args["Attributes"]
        self.assertEqual(len(attributes), 4)
        self.assertIn({"Key": "deregistration_delay.timeout_seconds", "Value": "300"}, attributes)
        self.assertIn({"Key": "stickiness.enabled", "Value": "true"}, attributes)
        self.assertIn({"Key": "stickiness.type", "Value": "lb_cookie"}, attributes)
        self.assertIn({"Key": "stickiness.lb_cookie.duration_seconds", "Value": "86400"}, attributes)

    def test_process_tags_annotations(self):
        annotations = {
            "aws.k8s.io.targetGroup/tag.Environment": "production",
            "aws.k8s.io.targetGroup/tag.Team": "platform"
        }

        changes_made = process_target_group_annotations(self.mock_elbv2, self.target_group_arn, annotations)
        
        self.assertTrue(changes_made)
        self.mock_elbv2.add_tags.assert_called_once()
        call_args = self.mock_elbv2.add_tags.call_args[1]
        self.assertEqual(call_args["ResourceArns"], [self.target_group_arn])
        
        tags = call_args["Tags"]
        self.assertEqual(len(tags), 2)
        self.assertIn({"Key": "Environment", "Value": "production"}, tags)
        self.assertIn({"Key": "Team", "Value": "platform"}, tags)

    def test_http_health_check_without_path(self):
        annotations = {
            "aws.k8s.io.targetGroup/healthCheck.enabled": "true",
            "aws.k8s.io.targetGroup/healthCheck.protocol": "HTTP",
            "aws.k8s.io.targetGroup/healthCheck.port": "traffic-port"
        }

        # Mock describe_target_groups response
        self.mock_elbv2.describe_target_groups.return_value = {
            'TargetGroups': [{
                'TargetGroupArn': self.target_group_arn,
                'HealthCheckProtocol': 'HTTP'
            }]
        }

        with self.assertRaises(kopf.PermanentError) as context:
            process_target_group_annotations(self.mock_elbv2, self.target_group_arn, annotations)
        
        self.assertIn("HealthCheckPath is required for HTTP/HTTPS health checks", str(context.exception))

    def test_tcp_health_check_without_path(self):
        annotations = {
            "aws.k8s.io.targetGroup/healthCheck.enabled": "true",
            "aws.k8s.io.targetGroup/healthCheck.protocol": "TCP",
            "aws.k8s.io.targetGroup/healthCheck.port": "traffic-port"
        }

        # Mock describe_target_groups response
        self.mock_elbv2.describe_target_groups.return_value = {
            'TargetGroups': [{
                'TargetGroupArn': self.target_group_arn,
                'HealthCheckProtocol': 'TCP'
            }]
        }

        changes_made = process_target_group_annotations(self.mock_elbv2, self.target_group_arn, annotations)
        self.assertTrue(changes_made)
        self.mock_elbv2.modify_target_group.assert_called_once()

    def test_health_check_validation_error(self):
        annotations = {
            "aws.k8s.io.targetGroup/healthCheck.enabled": "true",
            "aws.k8s.io.targetGroup/healthCheck.protocol": "HTTP",
            "aws.k8s.io.targetGroup/healthCheck.port": "traffic-port"
        }

        # Mock describe_target_groups response
        self.mock_elbv2.describe_target_groups.return_value = {
            'TargetGroups': [{
                'TargetGroupArn': self.target_group_arn,
                'HealthCheckProtocol': 'HTTP'
            }]
        }

        # Mock AWS ValidationError
        error_response = {
            'Error': {
                'Code': 'ValidationError',
                'Message': 'Path and return code are required for layer 7 health checks'
            }
        }
        self.mock_elbv2.modify_target_group.side_effect = ClientError(error_response, 'ModifyTargetGroup')

        with self.assertRaises(kopf.PermanentError) as context:
            process_target_group_annotations(self.mock_elbv2, self.target_group_arn, annotations)
        
        self.assertIn("Health check path is required for HTTP/HTTPS health checks", str(context.exception))

if __name__ == '__main__':
    unittest.main()