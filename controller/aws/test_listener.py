import unittest
from unittest.mock import MagicMock, patch
from .listener import find_target_group_rules, cleanup_target_group_rules, get_listener_rules, delete_listener
import kopf
from botocore.exceptions import ClientError

class TestListener(unittest.TestCase):
    def setUp(self):
        self.mock_elbv2 = MagicMock()
        self.target_group_arn = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/abcdef123'
        self.region = 'us-east-1'

    def test_find_target_group_rules_with_default_actions(self):
        """Test finding target group rules when target group is used in default actions"""
        # Mock load balancer response
        self.mock_elbv2.describe_load_balancers.return_value = {
            'LoadBalancers': [{
                'LoadBalancerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-lb/abcdef123'
            }]
        }

        # Mock listener response with target group in default action
        self.mock_elbv2.describe_listeners.return_value = {
            'Listeners': [{
                'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-lb/abcdef123/ghijkl456',
                'DefaultActions': [{
                    'Type': 'forward',
                    'TargetGroupArn': self.target_group_arn
                }]
            }]
        }

        # Mock rules response
        self.mock_elbv2.describe_rules.return_value = {
            'Rules': []
        }

        rules = find_target_group_rules(self.mock_elbv2, self.target_group_arn, self.region)

        # Should find one rule (the default action)
        self.assertEqual(len(rules), 1)
        self.assertIsNone(rules[0]['RuleArn'])  # Default actions don't have rule ARNs
        self.assertTrue(rules[0]['IsDefault'])

    def test_find_target_group_rules_with_non_default_rules(self):
        """Test finding target group rules when target group is used in non-default rules"""
        # Mock load balancer response
        self.mock_elbv2.describe_load_balancers.return_value = {
            'LoadBalancers': [{
                'LoadBalancerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-lb/abcdef123'
            }]
        }

        # Mock listener response with different target group in default action
        self.mock_elbv2.describe_listeners.return_value = {
            'Listeners': [{
                'ListenerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test-lb/abcdef123/ghijkl456',
                'DefaultActions': [{
                    'Type': 'forward',
                    'TargetGroupArn': 'different-target-group-arn'
                }]
            }]
        }

        # Mock rules response with our target group
        self.mock_elbv2.describe_rules.return_value = {
            'Rules': [{
                'RuleArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener-rule/app/test-lb/abcdef123/ghijkl456/mnopqr789',
                'Actions': [{
                    'Type': 'forward',
                    'TargetGroupArn': self.target_group_arn
                }]
            }]
        }

        rules = find_target_group_rules(self.mock_elbv2, self.target_group_arn, self.region)

        # Should find one rule (the non-default rule)
        self.assertEqual(len(rules), 1)
        self.assertIsNotNone(rules[0]['RuleArn'])
        self.assertFalse(rules[0]['IsDefault'])

    def test_cleanup_target_group_rules_with_default_rule_deletes_listener(self):
        """Test cleaning up when target group is used in default rule - should delete listener"""
        # Mock finding rules that include a default action
        with patch('controller.aws.listener.find_target_group_rules') as mock_find:
            mock_find.return_value = [{
                'RuleArn': None,
                'ListenerArn': 'listener-arn-1',
                'IsDefault': True
            }]
            
            # Mock describe_listeners to return HTTP listener
            self.mock_elbv2.describe_listeners.return_value = {
                'Listeners': [{
                    'Protocol': 'HTTP',
                    'Port': 80
                }]
            }

            # Mock describe_rules to return just the default rule
            self.mock_elbv2.describe_rules.return_value = {
                'Rules': [{
                    'RuleArn': None,
                    'IsDefault': True
                }]
            }

            cleanup_target_group_rules(self.mock_elbv2, self.target_group_arn, 80)

            # Should attempt to delete the listener
            self.mock_elbv2.delete_listener.assert_called_once_with(
                ListenerArn='listener-arn-1'
            )
            # Should not attempt to modify or delete rules since listener is deleted
            self.mock_elbv2.modify_listener.assert_not_called()
            self.mock_elbv2.delete_rule.assert_not_called()

    def test_cleanup_target_group_rules_with_all_rules_deletes_listener(self):
        """Test cleaning up when all rules in listener are being deleted - should delete listener"""
        # Mock finding rules that include all non-default rules
        with patch('controller.aws.listener.find_target_group_rules') as mock_find:
            mock_find.return_value = [{
                'RuleArn': 'rule-arn-1',
                'ListenerArn': 'listener-arn-1',
                'IsDefault': False
            }]
            
            # Mock describe_listeners
            self.mock_elbv2.describe_listeners.return_value = {
                'Listeners': [{
                    'Protocol': 'HTTP',
                    'Port': 80
                }]
            }

            # Mock describe_rules to return just one non-default rule and the default rule
            self.mock_elbv2.describe_rules.return_value = {
                'Rules': [{
                    'RuleArn': None,
                    'IsDefault': True
                }, {
                    'RuleArn': 'rule-arn-1',
                    'IsDefault': False
                }]
            }

            cleanup_target_group_rules(self.mock_elbv2, self.target_group_arn, 80)

            # Should attempt to delete the listener
            self.mock_elbv2.delete_listener.assert_called_once_with(
                ListenerArn='listener-arn-1'
            )
            # Should not attempt to modify or delete rules since listener is deleted
            self.mock_elbv2.modify_listener.assert_not_called()
            self.mock_elbv2.delete_rule.assert_not_called()

    def test_cleanup_target_group_rules_with_listener_delete_failure(self):
        """Test cleaning up when listener deletion fails - should fall back to rule cleanup"""
        # Mock finding rules that include a default action
        with patch('controller.aws.listener.find_target_group_rules') as mock_find:
            mock_find.return_value = [{
                'RuleArn': None,
                'ListenerArn': 'listener-arn-1',
                'IsDefault': True
            }]
            
            # Mock describe_listeners to return HTTP listener
            self.mock_elbv2.describe_listeners.return_value = {
                'Listeners': [{
                    'Protocol': 'HTTP',
                    'Port': 80
                }]
            }

            # Mock describe_rules to return just the default rule
            self.mock_elbv2.describe_rules.return_value = {
                'Rules': [{
                    'RuleArn': None,
                    'IsDefault': True
                }]
            }

            # Mock delete_listener to fail
            self.mock_elbv2.delete_listener.side_effect = ClientError(
                {'Error': {'Code': 'ListenerNotFound', 'Message': 'Listener not found'}},
                'DeleteListener'
            )

            cleanup_target_group_rules(self.mock_elbv2, self.target_group_arn, 80)

            # Should attempt to delete the listener
            self.mock_elbv2.delete_listener.assert_called_once_with(
                ListenerArn='listener-arn-1'
            )
            # Should fall back to modifying the default rule
            self.mock_elbv2.modify_listener.assert_called_once_with(
                ListenerArn='listener-arn-1',
                DefaultActions=[{
                    'Type': 'fixed-response',
                    'FixedResponseConfig': {
                        'ContentType': 'text/plain',
                        'StatusCode': '404',
                        'MessageBody': 'No target group available'
                    }
                }]
            )

    def test_cleanup_target_group_rules_with_some_rules(self):
        """Test cleaning up when only some rules in listener are being deleted"""
        # Mock finding rules that include one non-default rule
        with patch('controller.aws.listener.find_target_group_rules') as mock_find:
            mock_find.return_value = [{
                'RuleArn': 'rule-arn-1',
                'ListenerArn': 'listener-arn-1',
                'IsDefault': False
            }]
            
            # Mock describe_listeners
            self.mock_elbv2.describe_listeners.return_value = {
                'Listeners': [{
                    'Protocol': 'HTTP',
                    'Port': 80
                }]
            }

            # Mock describe_rules to return multiple rules
            self.mock_elbv2.describe_rules.return_value = {
                'Rules': [{
                    'RuleArn': None,
                    'IsDefault': True
                }, {
                    'RuleArn': 'rule-arn-1',
                    'IsDefault': False
                }, {
                    'RuleArn': 'rule-arn-2',
                    'IsDefault': False
                }]
            }

            cleanup_target_group_rules(self.mock_elbv2, self.target_group_arn, 80)

            # Should not attempt to delete the listener since there are other rules
            self.mock_elbv2.delete_listener.assert_not_called()
            # Should delete the specific rule
            self.mock_elbv2.delete_rule.assert_called_once_with(
                RuleArn='rule-arn-1'
            )

    def test_cleanup_target_group_rules_handles_errors(self):
        """Test that cleanup handles errors gracefully"""
        # Mock finding rules
        with patch('controller.aws.listener.find_target_group_rules') as mock_find:
            mock_find.return_value = [{
                'RuleArn': 'rule-arn-1',
                'ListenerArn': 'listener-arn-1',
                'IsDefault': False
            }]

            # Mock describe_rules to return multiple rules
            self.mock_elbv2.describe_rules.return_value = {
                'Rules': [{
                    'RuleArn': None,
                    'IsDefault': True
                }, {
                    'RuleArn': 'rule-arn-1',
                    'IsDefault': False
                }, {
                    'RuleArn': 'rule-arn-2',
                    'IsDefault': False
                }]
            }

            # Mock delete_rule to fail
            self.mock_elbv2.delete_rule.side_effect = ClientError(
                {'Error': {'Code': 'RuleNotFound', 'Message': 'Rule not found'}},
                'DeleteRule'
            )

            # Should raise a PermanentError
            with self.assertRaises(kopf.PermanentError):
                cleanup_target_group_rules(self.mock_elbv2, self.target_group_arn, self.region)

if __name__ == '__main__':
    unittest.main()