from typing import Dict, Any, List
import logging
import kopf
from botocore.exceptions import ClientError
from .client import retry_aws_operation, get_elbv2_client

logger = logging.getLogger(__name__)

def process_target_group_annotations(elbv2: Any, target_group_arn: str, annotations: Dict[str, str], region: str = None) -> bool:
    """
    Process target group annotations and apply changes.
    
    Args:
        elbv2: AWS ELBv2 client
        target_group_arn: ARN of the target group
        annotations: Annotations to process
        region: AWS region (optional)
        
    Returns:
        bool: True if changes were made, False otherwise
        
    Raises:
        kopf.PermanentError: If required health check parameters are missing
    """
    changes_made = False
    
    try:
        # Process health check configuration
        health_check_prefix = "aws.k8s.io.targetGroup/healthCheck."
        health_check_params = {}
        
        for key, value in annotations.items():
            if key.startswith(health_check_prefix):
                param_name = key[len(health_check_prefix):]
                if param_name == "enabled" and value.lower() == "true":
                    for hc_key, hc_value in annotations.items():
                        if hc_key.startswith(health_check_prefix):
                            hc_param = hc_key[len(health_check_prefix):]
                            try:
                                # Map annotation parameters to AWS SDK parameters
                                param_mapping = {
                                    "protocol": "HealthCheckProtocol",
                                    "port": "HealthCheckPort",
                                    "path": "HealthCheckPath",
                                    "enabled": "HealthCheckEnabled",
                                    "healthyThresholdCount": "HealthyThresholdCount",
                                    "unhealthyThresholdCount": "UnhealthyThresholdCount",
                                    "intervalSeconds": "HealthCheckIntervalSeconds",
                                    "timeoutSeconds": "HealthCheckTimeoutSeconds"
                                }
                                
                                aws_param = param_mapping.get(hc_param)
                                if not aws_param:
                                    logger.warning(f"Unknown health check parameter: {hc_param}")
                                    continue
                                    
                                if aws_param in ["HealthyThresholdCount", "UnhealthyThresholdCount",
                                             "HealthCheckIntervalSeconds", "HealthCheckTimeoutSeconds"]:
                                    health_check_params[aws_param] = int(hc_value)
                                elif aws_param == "HealthCheckEnabled":
                                    health_check_params[aws_param] = value.lower() == "true"
                                else:
                                    health_check_params[aws_param] = hc_value
                            except ValueError as e:
                                logger.warning(f"Invalid value for health check parameter {hc_param}: {str(e)}")
                    break

        if health_check_params:
            # Get target group details to determine load balancer type
            try:
                tg_details = retry_aws_operation(
                    elbv2.describe_target_groups,
                    TargetGroupArns=[target_group_arn]
                )['TargetGroups'][0]
                
                # Validate required parameters based on target group protocol
                protocol = health_check_params.get('HealthCheckProtocol', tg_details.get('HealthCheckProtocol'))
                if protocol in ['HTTP', 'HTTPS']:
                    # For HTTP/HTTPS health checks, path is required
                    if 'HealthCheckPath' not in health_check_params:
                        raise kopf.PermanentError("HealthCheckPath is required for HTTP/HTTPS health checks")
                
                health_check_params['TargetGroupArn'] = target_group_arn
                try:
                    retry_aws_operation(elbv2.modify_target_group, **health_check_params)
                    changes_made = True
                    logger.info("Successfully updated target group health check configuration")
                except ClientError as e:
                    if "ValidationError" in str(e):
                        error_msg = str(e)
                        if "Path and return code are required" in error_msg:
                            raise kopf.PermanentError("Health check path is required for HTTP/HTTPS health checks")
                        else:
                            raise kopf.PermanentError(f"AWS validation error: {error_msg}")
                    logger.error(f"Failed to update health check configuration: {str(e)}")
                    raise
            except ClientError as e:
                logger.error(f"Failed to get target group details: {str(e)}")
                raise

        # Process target group attributes
        attributes_prefix = "aws.k8s.io.targetGroup/attribute."
        attributes = []
        for key, value in annotations.items():
            if key.startswith(attributes_prefix):
                attr_name = key[len(attributes_prefix):]
                attributes.append({
                    'Key': attr_name,
                    'Value': str(value)
                })
        
        if attributes:
            try:
                retry_aws_operation(
                    elbv2.modify_target_group_attributes,
                    TargetGroupArn=target_group_arn,
                    Attributes=attributes
                )
                changes_made = True
                logger.info("Successfully updated target group attributes")
            except ClientError as e:
                logger.error(f"Failed to update target group attributes: {str(e)}")
                raise

        # Process tags
        tags_prefix = "aws.k8s.io.targetGroup/tag."
        tags = []
        for key, value in annotations.items():
            if key.startswith(tags_prefix):
                tag_key = key[len(tags_prefix):]
                tags.append({
                    'Key': tag_key,
                    'Value': value
                })
        
        if tags:
            try:
                retry_aws_operation(
                    elbv2.add_tags,
                    ResourceArns=[target_group_arn],
                    Tags=tags
                )
                changes_made = True
                logger.info("Successfully updated target group tags")
            except ClientError as e:
                logger.error(f"Failed to update target group tags: {str(e)}")
                raise
                
        return changes_made
        
    except Exception as e:
        logger.error(f"Error processing target group annotations: {str(e)}", exc_info=True)
        raise

def reconcile_target_group(elbv2: Any, target_group_arn: str, desired_config: Dict[str, Any], annotations: Dict[str, str] = None, region: str = None) -> bool:
    """
    Reconcile the AWS Target Group configuration with the desired state.
    
    Args:
        elbv2: AWS ELBv2 client
        target_group_arn: ARN of the target group
        desired_config: Desired configuration for the target group
        annotations: Optional annotations to process
        region: AWS region (optional)
        
    Returns:
        bool: True if changes were made, False otherwise
        
    Raises:
        kopf.PermanentError: If reconciliation fails permanently
    """
    try:
        changes_made = False
        logger.info(f"Starting reconciliation for target group: {target_group_arn}")
        
        # Get current target group attributes
        try:
            current_tg = retry_aws_operation(
                elbv2.describe_target_groups,
                TargetGroupArns=[target_group_arn]
            )['TargetGroups'][0]
        except ClientError as e:
            logger.error(f"Failed to describe target group: {str(e)}")
            raise kopf.PermanentError(f"Failed to describe target group: {str(e)}")
        
        # Prepare modification attributes
        modify_attrs = {}
        
        # Check and update protocol if different
        if current_tg['Protocol'] != desired_config['protocol']:
            modify_attrs['Protocol'] = desired_config['protocol']
            logger.info(f"Protocol change detected: {current_tg['Protocol']} -> {desired_config['protocol']}")
            
        # Check and update port if different
        if current_tg['Port'] != desired_config['port']:
            modify_attrs['Port'] = desired_config['port']
            logger.info(f"Port change detected: {current_tg['Port']} -> {desired_config['port']}")
            
        # If there are changes to be made
        if modify_attrs:
            modify_attrs['TargetGroupArn'] = target_group_arn
            try:
                retry_aws_operation(elbv2.modify_target_group, **modify_attrs)
                changes_made = True
                logger.info("Successfully updated target group basic attributes")
            except ClientError as e:
                logger.error(f"Failed to modify target group: {str(e)}")
                raise kopf.PermanentError(f"Failed to modify target group: {str(e)}")

        # Process annotations if provided
        if annotations:
            changes_made |= process_target_group_annotations(elbv2, target_group_arn, annotations)
                
        return changes_made
        
    except Exception as e:
        logger.error(f"Error reconciling target group: {str(e)}", exc_info=True)
        raise kopf.PermanentError(f"Failed to reconcile target group: {str(e)}")