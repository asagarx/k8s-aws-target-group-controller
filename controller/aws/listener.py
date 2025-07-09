from typing import Dict, Any, List
import logging
import kopf
from botocore.exceptions import ClientError
from .client import retry_aws_operation, get_elbv2_client

logger = logging.getLogger(__name__)

def get_load_balancer_info(elbv2: Any, name: str, region: str = None) -> Dict[str, str]:
    """
    Get the ARN and type of a load balancer by its name.
    
    Args:
        elbv2: AWS ELBv2 client
        name: Name of the load balancer
        region: AWS region (optional)
        
    Returns:
        Dict containing 'arn' and 'type' of the load balancer
        
    Raises:
        kopf.PermanentError: If load balancer is not found
    """
    try:
        response = retry_aws_operation(
            elbv2.describe_load_balancers,
            Names=[name]
        )
        if not response['LoadBalancers']:
            raise kopf.PermanentError(f"Load balancer {name} not found")
        lb = response['LoadBalancers'][0]
        return {
            'arn': lb['LoadBalancerArn'],
            'type': lb['Type']
        }
    except ClientError as e:
        if "LoadBalancerNotFound" in str(e):
            raise kopf.PermanentError(f"Load balancer {name} not found")
        raise kopf.PermanentError(f"Error getting load balancer info: {str(e)}")

def get_listener_arn(elbv2: Any, lb_arn: str, port: int, protocol: str, region: str = None) -> str:
    """
    Get the ARN of a listener by its port and protocol.
    
    Args:
        elbv2: AWS ELBv2 client
        lb_arn: ARN of the load balancer
        port: Port number
        protocol: Protocol (HTTP/HTTPS/TCP)
        region: AWS region (optional)
        
    Returns:
        str: ARN of the listener
        
    Raises:
        kopf.PermanentError: If listener is not found
    """
    try:
        response = retry_aws_operation(
            elbv2.describe_listeners,
            LoadBalancerArn=lb_arn
        )
        for listener in response['Listeners']:
            if listener['Port'] == port and listener['Protocol'] == protocol:
                return listener['ListenerArn']
        raise kopf.PermanentError(f"Listener not found for port {port} and protocol {protocol}")
    except ClientError as e:
        raise kopf.PermanentError(f"Error getting listener ARN: {str(e)}")

def create_alb_listener(elbv2: Any, lb_arn: str, port: int, protocol: str, certificate_arn: str = None, region: str = None) -> str:
    """
    Create an Application Load Balancer listener.
    
    Args:
        elbv2: AWS ELBv2 client
        lb_arn: ARN of the load balancer
        port: Port number
        protocol: Protocol (HTTP/HTTPS)
        certificate_arn: ARN of the SSL certificate (required for HTTPS)
        region: AWS region (optional)
        
    Returns:
        str: ARN of the created listener
        
    Raises:
        kopf.PermanentError: If listener creation fails or if certificate is missing for HTTPS
    """
    try:
        if protocol == 'HTTPS' and not certificate_arn:
            raise kopf.PermanentError("Certificate ARN is required for HTTPS listeners")

        create_params = {
            'LoadBalancerArn': lb_arn,
            'Protocol': protocol,
            'Port': port,
            'DefaultActions': [{
                'Type': 'fixed-response',
                'FixedResponseConfig': {
                    'ContentType': 'text/plain',
                    'StatusCode': '404',
                    'MessageBody': 'No matching rule'
                }
            }]
        }

        if protocol == 'HTTPS':
            create_params['Certificates'] = [{
                'CertificateArn': certificate_arn
            }]

        response = retry_aws_operation(
            elbv2.create_listener,
            **create_params
        )
        return response['Listeners'][0]['ListenerArn']
    except ClientError as e:
        raise kopf.PermanentError(f"Error creating ALB listener: {str(e)}")

def create_nlb_listener(elbv2: Any, lb_arn: str, port: int, protocol: str, target_group_arn: str, certificate_arn: str = None, region: str = None) -> str:
    """
    Create a Network Load Balancer listener.
    
    Args:
        elbv2: AWS ELBv2 client
        lb_arn: ARN of the load balancer
        port: Port number
        protocol: Protocol (TCP/TLS/UDP/TCP_UDP)
        target_group_arn: ARN of the target group for default action
        certificate_arn: ARN of the SSL certificate (required for TLS)
        region: AWS region (optional)
        
    Returns:
        str: ARN of the created listener
        
    Raises:
        kopf.PermanentError: If listener creation fails or if certificate is missing for TLS
    """
    try:
        if protocol == 'TLS' and not certificate_arn:
            raise kopf.PermanentError("Certificate ARN is required for TLS listeners")

        create_params = {
            'LoadBalancerArn': lb_arn,
            'Protocol': protocol,
            'Port': port,
            'DefaultActions': [{
                'Type': 'forward',
                'TargetGroupArn': target_group_arn
            }]
        }

        if protocol == 'TLS':
            create_params['Certificates'] = [{
                'CertificateArn': certificate_arn
            }]

        response = retry_aws_operation(
            elbv2.create_listener,
            **create_params
        )
        return response['Listeners'][0]['ListenerArn']
    except ClientError as e:
        raise kopf.PermanentError(f"Error creating NLB listener: {str(e)}")

def create_listener_rule(elbv2: Any, listener_arn: str, target_group_arn: str, priority: int, conditions: list, region: str = None) -> str:
    """
    Create a listener rule to forward traffic to the target group.
    
    Args:
        elbv2: AWS ELBv2 client
        listener_arn: ARN of the listener
        target_group_arn: ARN of the target group
        priority: Rule priority
        conditions: List of rule conditions
        region: AWS region (optional)
        
    Returns:
        str: ARN of the created rule
        
    Raises:
        kopf.PermanentError: If rule creation fails
    """
    try:
        # Transform conditions to AWS format
        aws_conditions = []
        for condition in conditions:
            field = condition['field']
            values = condition['values']
            
            if field == 'path-pattern':
                aws_conditions.append({
                    'Field': 'path-pattern',
                    'PathPatternConfig': {
                        'Values': values
                    }
                })
            elif field == 'host-header':
                aws_conditions.append({
                    'Field': 'host-header',
                    'HostHeaderConfig': {
                        'Values': values
                    }
                })
        
        response = retry_aws_operation(
            elbv2.create_rule,
            ListenerArn=listener_arn,
            Priority=priority,
            Conditions=aws_conditions,
            Actions=[{
                'Type': 'forward',
                'TargetGroupArn': target_group_arn
            }]
        )
        return response['Rules'][0]['RuleArn']
    except ClientError as e:
        raise kopf.PermanentError(f"Error creating listener rule: {str(e)}")

def compare_conditions(aws_conditions: List[Dict], desired_conditions: List[Dict]) -> bool:
    """Compare AWS conditions with desired conditions."""
    if len(aws_conditions) != len(desired_conditions):
        return False
        
    for aws_cond, desired_cond in zip(aws_conditions, desired_conditions):
        aws_field = aws_cond.get('Field', '').lower()
        desired_field = desired_cond.get('field', '').lower().replace('-', '')
        
        if aws_field != desired_field:
            return False
            
        aws_values = set()
        desired_values = set(desired_cond.get('values', []))
        
        if aws_field == 'pathpattern':
            aws_values = set(aws_cond.get('PathPatternConfig', {}).get('Values', []))
        elif aws_field == 'hostheader':
            aws_values = set(aws_cond.get('HostHeaderConfig', {}).get('Values', []))
            
        if aws_values != desired_values:
            return False
            
    return True

def find_target_group_rules(elbv2: Any, target_group_arn: str, region: str = None) -> List[Dict[str, Any]]:
    """
    Find all listener rules that reference a target group.
    
    Args:
        elbv2: AWS ELBv2 client
        target_group_arn: ARN of the target group
        region: AWS region (optional)
        
    Returns:
        List[Dict]: List of rules that reference the target group
    """
    rules = []
    try:
        # First get all load balancers
        lbs = retry_aws_operation(elbv2.describe_load_balancers)
        
        # For each load balancer, get its listeners
        for lb in lbs['LoadBalancers']:
            listeners = retry_aws_operation(
                elbv2.describe_listeners,
                LoadBalancerArn=lb['LoadBalancerArn']
            )
            
            # For each listener, get its rules
            for listener in listeners['Listeners']:
                # Check default action
                for action in listener['DefaultActions']:
                    if action['Type'] == 'forward' and action.get('TargetGroupArn') == target_group_arn:
                        rules.append({
                            'RuleArn': None,  # No ARN for default action
                            'ListenerArn': listener['ListenerArn'],
                            'IsDefault': True
                        })
                
                # Check non-default rules
                listener_rules = retry_aws_operation(
                    elbv2.describe_rules,
                    ListenerArn=listener['ListenerArn']
                )
                
                for rule in listener_rules['Rules']:
                    for action in rule['Actions']:
                        if action['Type'] == 'forward' and action.get('TargetGroupArn') == target_group_arn:
                            rules.append({
                                'RuleArn': rule['RuleArn'],
                                'ListenerArn': listener['ListenerArn'],
                                'IsDefault': False
                            })
                            
    except ClientError as e:
        logger.error(f"Error finding target group rules: {str(e)}")
        raise kopf.PermanentError(f"Error finding target group rules: {str(e)}")
        
    return rules

def get_listener_rules(elbv2: Any, listener_arn: str) -> List[Dict[str, Any]]:
    """
    Get all rules for a listener.
    
    Args:
        elbv2: AWS ELBv2 client
        listener_arn: ARN of the listener
        
    Returns:
        List[Dict]: List of rules for the listener
    """
    try:
        response = retry_aws_operation(
            elbv2.describe_rules,
            ListenerArn=listener_arn
        )
        return response['Rules']
    except ClientError as e:
        logger.error(f"Error getting rules for listener {listener_arn}: {str(e)}")
        raise kopf.PermanentError(f"Error getting rules for listener {listener_arn}: {str(e)}")

def delete_listener(elbv2: Any, listener_arn: str) -> None:
    """
    Delete a listener.
    
    Args:
        elbv2: AWS ELBv2 client
        listener_arn: ARN of the listener
        
    Raises:
        kopf.PermanentError: If deletion fails
    """
    try:
        retry_aws_operation(
            elbv2.delete_listener,
            ListenerArn=listener_arn
        )
        logger.info(f"Successfully deleted listener {listener_arn}")
    except ClientError as e:
        logger.error(f"Error deleting listener {listener_arn}: {str(e)}")
        raise kopf.PermanentError(f"Error deleting listener {listener_arn}: {str(e)}")

def cleanup_target_group_rules(elbv2: Any, target_group_arn: str, listener_port: int, load_balancer_arn: str = None, region: str = None) -> None:
    """
    Clean up all listener rules and listeners that reference a target group.
    If a rule being deleted is the only rule in the listener or is the default rule,
    the entire listener will be deleted instead.
    
    Args:
        elbv2: AWS ELBv2 client
        target_group_arn: ARN of the target group
        listener_port: Port of the listener to target for cleanup
        load_balancer_arn: ARN of the load balancer (optional, for direct lookup)
        region: AWS region (optional)
        
    Raises:
        kopf.PermanentError: If cleanup fails
    """
    try:
        rules = []
        # If we have the load balancer ARN, we can directly get its listeners
        if load_balancer_arn:
            try:
                listeners = retry_aws_operation(
                    elbv2.describe_listeners,
                    LoadBalancerArn=load_balancer_arn
                )
                
                # Filter listeners by port and check rules
                for listener in listeners['Listeners']:
                    if listener['Port'] == listener_port:
                        # Check default action
                        for action in listener['DefaultActions']:
                            if action['Type'] == 'forward' and action.get('TargetGroupArn') == target_group_arn:
                                rules.append({
                                    'RuleArn': None,
                                    'ListenerArn': listener['ListenerArn'],
                                    'IsDefault': True
                                })
                        
                        # Check non-default rules
                        listener_rules = retry_aws_operation(
                            elbv2.describe_rules,
                            ListenerArn=listener['ListenerArn']
                        )
                        
                        for rule in listener_rules['Rules']:
                            for action in rule['Actions']:
                                if action['Type'] == 'forward' and action.get('TargetGroupArn') == target_group_arn:
                                    rules.append({
                                        'RuleArn': rule['RuleArn'],
                                        'ListenerArn': listener['ListenerArn'],
                                        'IsDefault': False
                                    })
            except ClientError as e:
                logger.warning(f"Error getting listeners for load balancer {load_balancer_arn}: {str(e)}")
                # Fall back to searching all load balancers
                rules = find_target_group_rules(elbv2, target_group_arn, region)
        else:
            # If we don't have the load balancer ARN, search all load balancers
            rules = find_target_group_rules(elbv2, target_group_arn, region)
        
        # Track listeners and their rules for cleanup decision
        listener_rules = {}
        
        # Group rules by listener
        for rule in rules:
            listener_arn = rule['ListenerArn']
            if listener_arn not in listener_rules:
                listener_rules[listener_arn] = {'default': None, 'non_default': []}
            
            if rule['IsDefault']:
                listener_rules[listener_arn]['default'] = rule
            else:
                listener_rules[listener_arn]['non_default'].append(rule)
        
        # Process each listener
        for listener_arn, rules_info in listener_rules.items():
            try:
                # Get all rules for this listener
                all_listener_rules = get_listener_rules(elbv2, listener_arn)
                total_rules = len(all_listener_rules)
                
                # Get listener details to determine its protocol
                listener_details = retry_aws_operation(
                    elbv2.describe_listeners,
                    ListenerArns=[listener_arn]
                )['Listeners'][0]
                
                # Check if we should delete the entire listener:
                # 1. If the rule is the default rule
                # 2. If the rules we're deleting are all the rules in the listener
                if rules_info['default'] or len(rules_info['non_default']) == total_rules - 1:  # -1 for default rule
                    try:
                        delete_listener(elbv2, listener_arn)
                        continue  # Skip to next listener since this one is deleted
                    except kopf.PermanentError as e:
                        logger.warning(f"Failed to delete listener {listener_arn}, falling back to rule cleanup: {str(e)}")
                
                # If listener deletion failed or wasn't needed, proceed with rule cleanup
                # Delete non-default rules first
                for rule in rules_info['non_default']:
                    try:
                        retry_aws_operation(
                            elbv2.delete_rule,
                            RuleArn=rule['RuleArn']
                        )
                        logger.info(f"Successfully deleted rule {rule['RuleArn']}")
                    except ClientError as e:
                        logger.error(f"Error deleting rule {rule['RuleArn']}: {str(e)}")
                        raise
                
                # Handle default rules by modifying them instead of deleting if we couldn't delete the listener
                # if rules_info['default'] and listener_details['Protocol'] in ['HTTP', 'HTTPS']:
                #     default_action = [{
                #         'Type': 'fixed-response',
                #         'FixedResponseConfig': {
                #             'ContentType': 'text/plain',
                #             'StatusCode': '404',
                #             'MessageBody': 'No target group available'
                #         }
                #     }]
                    
                #     retry_aws_operation(
                #         elbv2.modify_listener,
                #         ListenerArn=listener_arn,
                #         DefaultActions=default_action
                #     )
                #     logger.info(f"Successfully updated default action for listener {listener_arn}")
                
            except ClientError as e:
                logger.error(f"Error processing listener {listener_arn}: {str(e)}")
                raise
                
    except Exception as e:
        logger.error(f"Error cleaning up target group rules: {str(e)}")
        raise kopf.PermanentError(f"Error cleaning up target group rules: {str(e)}")
    