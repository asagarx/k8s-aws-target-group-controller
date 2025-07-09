import kopf
import kubernetes
import logging
import threading
import time
import argparse
from typing import Dict, Any
from botocore.exceptions import ClientError
from .aws.client import get_elbv2_client
from .aws.target_group import reconcile_target_group
from .aws.listener import (
    get_load_balancer_info,
    get_listener_arn,
    create_alb_listener,
    create_nlb_listener,
    create_listener_rule
)
from .webhook.server import start_webhook_server

logger = logging.getLogger(__name__)

# Constants
FINALIZER_NAME = "aws.k8s.io/awstargetgroup-finalizer"
DEFAULT_CHECK_INTERVAL = 5  # Default interval in seconds for periodic checks

# Get check interval from environment variable or use default
import os
RECONCILE_INTERVAL = int(os.getenv('RECONCILE_INTERVAL', DEFAULT_CHECK_INTERVAL))

def create_target_group_bind(target_group_name, target_group_namespace, target_group_arn, target_group_spec):
    """
    function to create targetGroupBinding resource in the k8s cluster

    Args:
        target_group_name (string): name of the AWSTargetGroup CRD
        target_group_namespace (string): namespace of AWSTargetGroup CRD
    """
    
    binding_manifest = {
        'apiVersion': 'elbv2.k8s.aws/v1beta1',
        'kind': 'TargetGroupBinding',
        'metadata': {
            'name': target_group_name,
            'namespace': target_group_namespace,
            'labels': {
                'created-by': 'aws-targetgroup-operator',
                'targetgroup-name': target_group_name
            }
        },
        'spec': {
            'targetGroupARN': target_group_arn,
            'serviceRef': {
                'name': target_group_spec['serviceRef']['name'],
                'port': target_group_spec['serviceRef']['port']
            }
        }
    }
    
    print("59: binding manifest")
    print(binding_manifest)

    api = kubernetes.client.CustomObjectsApi()
    try:
        # Create the TargetGroupBinding resource
        api.create_namespaced_custom_object(
            group="elbv2.k8s.aws",
            version="v1beta1",
            plural="targetgroupbindings",
            namespace=target_group_namespace,
            body=binding_manifest
        )
        logger.info(f"Successfully created TargetGroupBinding {target_group_name}")
    except kubernetes.client.rest.ApiException as e:
        if e.status == 409:  # Already exists
            logger.info(f"TargetGroupBinding {target_group_name} already exists")
        else:
            logger.error(f"Failed to create TargetGroupBinding: {str(e)}")
            # Don't raise error as the target group was created successfully
    except Exception as e:
        logger.error(f"Error creating TargetGroupBinding: {str(e)}")
        # Don't raise error as the target group was created successfully

def periodic_check_awstargetgroups():
    """
    Periodically check for awstargetgroups resources and trigger create_fn if needed.
    The check interval can be configured using the RECONCILE_INTERVAL environment variable (in seconds).
    If not set, defaults to 5 seconds.
    """
    # Get check interval from environment variable
    check_interval = RECONCILE_INTERVAL
    logger.info(f"Starting periodic check with interval of {check_interval} seconds")
    
    # Load in-cluster configuration
    try:
        kubernetes.config.load_incluster_config()
    except kubernetes.config.ConfigException:
        # Fallback to kubeconfig for local development
        kubernetes.config.load_kube_config()
    
    while True:
        try:
            # Get Kubernetes API client
            api = kubernetes.client.CustomObjectsApi()
            
            # List awstargetgroups resources from all namespaces
            resources = api.list_namespaced_custom_object(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace=""
            )
            target_gps = []
            target_gp_binds = []
            target_gp_binds_name = []
            
            # Check each resource
            for item in resources.get('items', []):
                name = item['metadata']['name']
                metadata = item['metadata']
                status = item.get('status', {})
                namespace = metadata.get('namespace')
                spec = item['spec']

                
                # Check if resource is marked for deletion
                if metadata.get('deletionTimestamp'):
                    logger.info(f"Found awstargetgroup {name} marked for deletion")
                    if FINALIZER_NAME in metadata.get('finalizers', []):
                        try:
                            # Remove finalizer
                            api.patch_namespaced_custom_object(
                                group="aws.k8s.io",
                                version="v1",
                                plural="awstargetgroups",
                                namespace=namespace,
                                name=name,
                                body={
                                    "metadata": {
                                        "finalizers": [f for f in metadata.get('finalizers', []) if f != FINALIZER_NAME]
                                    }
                                }
                            )
                            logger.info(f"Successfully removed finalizer from {name}")
                        except Exception as e:
                            logger.error(f"Failed to remove finalizer from {name}: {str(e)}")
                    continue

                # If resource doesn't have targetGroupARN in status, trigger create_fn
                if not status.get('targetGroupArn'):
                    logger.info(f"Found awstargetgroup {name} without targetGroupARN, triggering creation")
                    try:
                        create_fn(
                            spec=item['spec'],
                            meta=metadata,
                            status=status,
                            logger=logger
                        )
                    except Exception as e:
                        logger.error(f"Failed to create target group for {name}: {str(e)}")
                        
                if not metadata.get('deletionTimestamp') and status.get('targetGroupArn'):
                    target_gps.append({
                            'name': name,
                            'namespace': namespace,
                            'target_group_arn': status.get('targetGroupArn'),
                            'spec': spec
                            
                        })
            # Checking for TargetGroupBindings
            tgpbind_resources = api.list_namespaced_custom_object(
                group="elbv2.k8s.aws",
                version="v1beta1",
                plural="targetgroupbindings",
                namespace=""
            )
            
                
            for item in tgpbind_resources.get('items', []):
                tgp_bind_name = item['metadata']['name']
                tgp_bind_namespace = item['metadata']['namespace']
                target_gp_binds.append({
                    'name': tgp_bind_name,
                    'namespace': tgp_bind_namespace
                })
                target_gp_binds_name.append(tgp_bind_name)
                
            # Checking the existance of targetgroupbinding
            for each_tgp in target_gps:
                tgp_name = each_tgp["name"]
                tgp_namespace = each_tgp["namespace"]
                if f"{tgp_name}-binding" in target_gp_binds_name:
                    for each_tgp_bind in target_gp_binds:
                        if each_tgp_bind["name"] == f"{tgp_name}-binding":
                            if tgp_namespace == each_tgp_bind["namespace"]:
                                continue
                            else:
                                logger.info(f"Found awstargetgroup {tgp_name} without TargetGroupBinding in namespace {tgp_namespace}, AWS targetgroup ARN: {each_tgp.target_group_arn}")
                                create_target_group_bind(f"{tgp_name}-binding", tgp_namespace, each_tgp["target_group_arn"], each_tgp["spec"])
                else:
                    if tgp_name != None:
                        create_target_group_bind(f"{tgp_name}-binding", tgp_namespace, each_tgp["target_group_arn"], each_tgp["spec"])
                         
        except Exception as e:
            logger.info(f"Found awstargetgroup {tgp_name} without TargetGroupBinding in namespace {tgp_namespace}, AWS targetgroup ARN: {each_tgp.target_group_arn}")
            logger.error(f"Error in periodic check: {str(e)}")
            
        # Sleep for configured interval before next check
        time.sleep(check_interval)

@kopf.on.startup()
def startup_fn(logger, **kwargs):
    """Initialize the operator and start the webhook server."""
    try:
        # Validate required environment variables
        k8s_cluster_name = os.getenv('K8S_CLUSTER_NAME')
        if not k8s_cluster_name:
            error_msg = "K8S_CLUSTER_NAME environment variable is required but not set"
            logger.error(error_msg)
            raise kopf.PermanentError(error_msg)

        webhook_thread = threading.Thread(target=start_webhook_server, daemon=True)
        webhook_thread.start()
        logger.info("Started webhook server in background thread")
        
        # Start the periodic check thread
        check_thread = threading.Thread(target=periodic_check_awstargetgroups, daemon=True)
        check_thread.start()
        logger.info("Started periodic check thread")
    except Exception as e:
        logger.error(f"Failed to start webhook server: {str(e)}", exc_info=True)
        raise kopf.PermanentError("Failed to start webhook server")

@kopf.on.create('aws.k8s.io', 'v1', 'awstargetgroups')
def create_fn(spec: Dict[str, Any], meta: Dict[str, Any], status: Dict[str, Any], logger: Any, **kwargs) -> Dict[str, Any]:
    """
    Handle creation of AWS Target Groups and associate them with load balancers.
    """
    logger.info(f"Creating AWS Target Group: {meta['name']}")
    tgp_protocol = spec["protocol"]
    
    # Add our finalizer to the resource
    # Get current finalizers
    finalizers = meta.get('finalizers', [])
    if FINALIZER_NAME not in finalizers:
        # Add our finalizer to the list
        finalizers.append(FINALIZER_NAME)
        # Update the resource with the new finalizers
        api = kubernetes.client.CustomObjectsApi()
        api.patch_namespaced_custom_object(
            group="aws.k8s.io",
            version="v1",
            plural="awstargetgroups",
            namespace=meta['namespace'],
            name=meta['name'],
            body={
                'metadata': {
                    'finalizers': finalizers
                }
            }
        )
    
    # Initialize AWS client with region from spec
    elbv2 = get_elbv2_client(region=spec.get('region'))
    
    try:
        # Get load balancer info
        lb_name = spec['loadBalancerRef']['name']
        region = spec.get('region')  # Get region from spec
        lb_info = get_load_balancer_info(elbv2, lb_name, region=region)
        lb_arn = lb_info['arn']
        lb_type = lb_info['type']
        logger.info(f"Found load balancer ARN: {lb_arn} of type: {lb_type} in region: {region}")
        
        # Validate required fields
        required_fields = ['protocol', 'port', 'vpcId', 'targetType', 'loadBalancerRef']
        missing_fields = [field for field in required_fields if field not in spec]
        if missing_fields:
            raise kopf.PermanentError(f"Missing required fields: {', '.join(missing_fields)}")
        
        # Valiadting targetGroup parameters with load balancre type
        if lb_type == "network":
            if tgp_protocol not in ['TCP', 'TLS', 'UDP', 'TCP_UDP']:
                error_msg = f"Invalid protocol {tgp_protocol} for targetgroup. Must be TCP, TLS, UDP, or TCP_UDP"
                logger.error(error_msg)
                raise kopf.PermanentError(error_msg)
        else:
            if tgp_protocol not in ['HTTP', 'HTTPS']:
                error_msg = f"Invalid protocol {tgp_protocol} for targetgroup. Must be HTTP or HTTPS"
                logger.error(error_msg)
                raise kopf.PermanentError(error_msg)
        
        # Get cluster name from environment
        k8s_cluster_name = os.getenv('K8S_CLUSTER_NAME')
        if not k8s_cluster_name:
            error_msg = "K8S_CLUSTER_NAME environment variable is required but not set"
            logger.error(error_msg)
            raise kopf.PermanentError(error_msg)

        # Format target group name with length validation
        # AWS Target Group name has a 32 character limit
        # We need to ensure name-namespace-cluster format while staying within limit
        MAX_LENGTH = 32
        name = meta['name']
        namespace = meta['namespace']
        
        # Calculate available space for each part
        # We need 2 hyphens, so that's 2 characters
        # Try to distribute remaining space evenly but prioritize the name
        remaining_space = MAX_LENGTH - 2  # Account for hyphens
        
        # First ensure k8s_cluster_name is not too long (give it 1/4 of space)
        cluster_max = remaining_space // 4
        k8s_cluster_short = k8s_cluster_name[:cluster_max]
        
        # Now divide remaining space between name and namespace, giving more to name
        remaining_space -= len(k8s_cluster_short)
        name_max = (remaining_space * 3) // 5  # Give 60% to name
        namespace_max = remaining_space - name_max
        
        # Truncate the parts
        name_short = name[:name_max]
        namespace_short = namespace[:namespace_max]
        
        # Format target group name
        target_group_name = f"{name_short}-{namespace_short}-{k8s_cluster_short}"
        target_group_arn = ""

        # Check if target group already exists
        try:
            existing_tgs = elbv2.describe_target_groups(Names=[target_group_name])
            if existing_tgs['TargetGroups']:
                target_group_arn = existing_tgs['TargetGroups'][0]['TargetGroupArn']
                logger.info(f"Found existing target group: {target_group_arn}")
        except elbv2.exceptions.TargetGroupNotFoundException:
            # Target group doesn't exist, proceed with creation
            pass

        # Get listener configuration from annotations
        annotations = meta.get('annotations', {})
        listener_port = int(annotations.get('aws.k8s.io.loadBalancer/listener.port', 0))
        listener_protocol = annotations.get('aws.k8s.io.loadBalancer/listener.protocol')
        listener_priority = int(annotations.get('aws.k8s.io.loadBalancer/listener.priority', 0))
        certificate_arn = annotations.get('aws.k8s.io.loadBalancer/listener.certificateArn')

        if not all([listener_port, listener_protocol, listener_priority]):
            error_msg = "Missing required listener configuration in annotations"
            logger.error(error_msg)
            raise kopf.PermanentError(error_msg)
            
        # Validate certificate ARN is present for HTTPS and TLS
        if ((listener_protocol == 'HTTPS') or listener_protocol == 'TLS') and not certificate_arn:
            error_msg = f"Certificate ARN is required for {listener_protocol} listeners"
            logger.error(error_msg)
            raise kopf.PermanentError(error_msg)

        # Validate protocol based on load balancer type
        if lb_type == 'application':
            if listener_protocol not in ['HTTP', 'HTTPS']:
                error_msg = f"Invalid protocol {listener_protocol} for ALB. Must be HTTP or HTTPS"
                logger.error(error_msg)
                raise kopf.PermanentError(error_msg)
        elif lb_type == 'network':
            if listener_protocol not in ['TCP', 'TLS', 'UDP', 'TCP_UDP']:
                error_msg = f"Invalid protocol {listener_protocol} for NLB. Must be TCP, TLS, UDP, or TCP_UDP"
                logger.error(error_msg)
                raise kopf.PermanentError(error_msg)

        # Parse listener conditions from annotations (only for ALB)
        conditions = []
        if lb_type == 'application':
            i = 0
            while True:
                field = annotations.get(f'aws.k8s.io.loadBalancer/listener.condition.{i}.field')
                values = annotations.get(f'aws.k8s.io.loadBalancer/listener.condition.{i}.values')
                if not field or not values:
                    break
                conditions.append({
                    'field': field,
                    'values': values.split(',')
                })
                i += 1

        # Create target group in AWS
        if target_group_arn == "":
            # Prepare target group creation parameters
            create_params = {
                'Name': target_group_name,
                'Protocol': spec['protocol'],
                'Port': spec['port'],
                'VpcId': spec['vpcId'],
                'TargetType': spec['targetType']
            }
            response = elbv2.create_target_group(**create_params)
            target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
            logger.info(f"Successfully created target group: {target_group_arn}")

        # Get or create listener
        try:
            listener_arn = get_listener_arn(elbv2, lb_arn, listener_port, listener_protocol, region=region)
            logger.info(f"Found existing listener ARN: {listener_arn}")
        except kopf.PermanentError:
            # Listener not found, create it based on load balancer type
            if lb_type == 'application':
                listener_arn = create_alb_listener(elbv2, lb_arn, listener_port, listener_protocol, certificate_arn if listener_protocol == 'HTTPS' else None, region=region)
            else:  # network
                listener_arn = create_nlb_listener(elbv2, lb_arn, listener_port, listener_protocol, target_group_arn, certificate_arn if listener_protocol == 'TLS' else None, region=region)
            logger.info(f"Created new {lb_type} listener: {listener_arn}")

        # Create listener rule for ALB only
        rule_arn = None
        if lb_type == 'application':
            rule_arn = create_listener_rule(elbv2, listener_arn, target_group_arn, listener_priority, conditions, region=region)
            logger.info(f"Created listener rule: {rule_arn}")

        # Process target group annotations
        reconcile_target_group(elbv2, target_group_arn, spec, meta.get('annotations', {}), region=region)

        # Prepare status update
        status_update = {
            'targetGroupArn': target_group_arn,
            'loadBalancerArn': lb_arn,  # Store the load balancer ARN
            'state': 'active',
            'ruleArn': rule_arn,
            'error': None
        }

        # Update the resource status
        try:
            api = kubernetes.client.CustomObjectsApi()
            api.patch_namespaced_custom_object_status(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace=meta['namespace'],
                name=meta['name'],
                body={'status': status_update}
            )
            logger.info(f"Successfully updated status for {meta['name']}")

            # Create TargetGroupBinding if serviceRef is specified in spec
            if 'serviceRef' in spec and 'port' in spec:
                # Prepare TargetGroupBinding manifest
                binding_name = f"{meta['name']}-binding"
                create_target_group_bind(binding_name, meta['namespace'], target_group_arn, spec)

        except Exception as e:
            logger.error(f"Failed to update status: {str(e)}", exc_info=True)
            # Don't raise error here as the target group was created successfully

        return status_update

    except Exception as e:
        logger.error(f"Error creating target group: {str(e)}", exc_info=True)
        
        # Try to update status with error state
        try:
            api = kubernetes.client.CustomObjectsApi()
            api.patch_namespaced_custom_object_status(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace=meta['namespace'],
                name=meta['name'],
                body={'status': {'state': 'error', 'error': str(e)}}
            )
        except Exception as status_e:
            logger.error(f"Failed to update error status: {str(status_e)}", exc_info=True)
        
        raise kopf.PermanentError(f"Failed to create target group: {str(e)}")

@kopf.on.delete('aws.k8s.io', 'v1', 'awstargetgroups')
def delete_fn(spec: Dict[str, Any], meta: Dict[str, Any], status: Dict[str, Any], logger: Any, **kwargs):
    """
    Handle deletion of AWS Target Groups and their associated TargetGroupBinding resources.
    """
    logger.info(f"Deleting AWS Target Group: {meta['name']}")
    
    # Get target group ARN from status
    target_group_arn = status.get('targetGroupArn')
    namespace = meta.get('namespace')
    
    if not target_group_arn:
        logger.warning("No target group ARN found in status, skipping deletion")
        return
    
    # Initialize AWS client with region from spec
    elbv2 = get_elbv2_client(region=spec.get('region'))
    k8s_api = kubernetes.client.CustomObjectsApi()
    
    try:
        # First, find and delete any associated TargetGroupBinding resources in the same namespace
        try:
            # Search for TargetGroupBindings only in the same namespace
            bindings = k8s_api.list_namespaced_custom_object(
                group="elbv2.k8s.aws",
                version="v1beta1",
                plural="targetgroupbindings",
                namespace=namespace
            )
            
            for binding in bindings.get('items', []):
                if binding['spec'].get('targetGroupARN') == target_group_arn:
                    binding_name = binding['metadata']['name']
                    logger.info(f"Found associated TargetGroupBinding {binding_name} in namespace {namespace}")
                    
                    try:
                        k8s_api.delete_namespaced_custom_object(
                            group="elbv2.k8s.aws",
                            version="v1beta1",
                            plural="targetgroupbindings",
                            namespace=namespace,
                            name=binding_name
                        )
                        logger.info(f"Successfully deleted TargetGroupBinding {binding_name}")
                    except kubernetes.client.rest.ApiException as e:
                        if e.status != 404:  # Ignore if already deleted
                            logger.warning(f"Error deleting TargetGroupBinding {binding_name}: {str(e)}")
                    
        except kubernetes.client.rest.ApiException as e:
            logger.warning(f"Error listing TargetGroupBindings: {str(e)}")
        
        # Then clean up any listener rules and listeners using this target group
        from .aws.listener import cleanup_target_group_rules
        try:
            # Get load balancer ARN from status if available
            load_balancer_arn = status.get('loadBalancerArn')
            
            # passing listener rule in to the cleanup for faster deletion
            target_group_annotations = meta.get('annotations', {})
            load_listener_port = int(target_group_annotations.get('aws.k8s.io.loadBalancer/listener.port', 0))
            
            cleanup_target_group_rules(elbv2, target_group_arn, load_listener_port, load_balancer_arn, region=spec.get('region'))
            logger.info("Successfully cleaned up listener rules and listeners")
        except Exception as e:
            logger.error(f"Error cleaning up listener rules and listeners: {str(e)}")
            raise
        
        # Finally delete the target group
        try:
            elbv2.delete_target_group(TargetGroupArn=target_group_arn)
            # Remove our finalizer from the list and update the resource
            api = kubernetes.client.CustomObjectsApi()
            finalizers = meta.get('finalizers', [])
            if FINALIZER_NAME in finalizers:
                finalizers.remove(FINALIZER_NAME)
                api.patch_namespaced_custom_object(
                    group="aws.k8s.io",
                    version="v1",
                    plural="awstargetgroups",
                    namespace=meta['namespace'],
                    name=meta['name'],
                    body={
                        'metadata': {
                            'finalizers': finalizers
                        }
                    }
                )
            logger.info(f"Successfully deleted target group: {target_group_arn}")
        except ClientError as e:
            if "ResourceInUse" in str(e):
                # If the target group is still in use after cleaning up rules,
                # there might be other resources using it that we don't manage
                logger.error(f"Target group is still in use after cleanup: {str(e)}")
                raise kopf.TemporaryError(
                    "Target group is still in use by other resources. Please check and remove these dependencies manually.",
                    delay=60  # Retry after 60 seconds
                )
            raise
    except Exception as e:
        logger.error(f"Error deleting target group: {str(e)}", exc_info=True)
        raise kopf.PermanentError(f"Failed to delete target group: {str(e)}")

@kopf.on.field('aws.k8s.io', 'v1', 'awstargetgroups', field='spec')
def spec_handler(spec: Dict[str, Any], meta: Dict[str, Any], status: Dict[str, Any], old: Dict[str, Any], new: Dict[str, Any], logger: Any, **kwargs):
    """
    Handle changes to the spec field of AWSTargetGroup resources.
    """
    logger.info(f"Handling spec change for AWS Target Group: {meta['name']}")
    
    # Get target group ARN from status
    target_group_arn = status.get('targetGroupArn')
    if not target_group_arn:
        logger.warning("No target group ARN found in status, skipping reconciliation")
        return
    
    # Initialize AWS client with region from spec
    elbv2 = get_elbv2_client(region=spec.get('region'))
    
    try:
        # Reconcile target group configuration
        changes_made = reconcile_target_group(elbv2, target_group_arn, new, meta.get('annotations', {}), region=spec.get('region'))
        if changes_made:
            logger.info(f"Successfully reconciled target group: {target_group_arn}")
            
            # Update status to reflect changes
            try:
                api = kubernetes.client.CustomObjectsApi()
                api.patch_namespaced_custom_object_status(
                    group="aws.k8s.io",
                    version="v1",
                    plural="awstargetgroups",
                    namespace=meta['namespace'],
                    name=meta['name'],
                    body={'status': {'targetGroupArn': target_group_arn, 'state': 'active'}}
                )
                logger.info(f"Successfully updated status for {meta['name']}")
            except Exception as e:
                logger.error(f"Failed to update status: {str(e)}", exc_info=True)
    except Exception as e:
        logger.error(f"Error reconciling target group: {str(e)}", exc_info=True)
        
        # Update status to reflect error
        try:
            api = kubernetes.client.CustomObjectsApi()
            api.patch_namespaced_custom_object_status(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace=meta['namespace'],
                name=meta['name'],
                body={'status': {'state': 'error', 'error': str(e)}}
            )
        except Exception as status_e:
            logger.error(f"Failed to update error status: {str(status_e)}", exc_info=True)
        
        raise kopf.PermanentError(f"Failed to reconcile target group: {str(e)}")

@kopf.on.field('aws.k8s.io', 'v1', 'awstargetgroups', field='metadata.annotations')
def annotations_handler(spec: Dict[str, Any], meta: Dict[str, Any], status: Dict[str, Any], old: Dict[str, Any], new: Dict[str, Any], logger: Any, **kwargs):
    """
    Handle changes to the annotations of AWSTargetGroup resources.
    """
    logger.info(f"Handling annotations change for AWS Target Group: {meta['name']}")
    
    # Get target group ARN from status
    target_group_arn = status.get('targetGroupArn')
    if not target_group_arn:
        logger.warning("No target group ARN found in status, skipping reconciliation")
        return
    
    # Initialize AWS client with region from spec
    elbv2 = get_elbv2_client(region=spec.get('region'))
    
    try:
        # Reconcile target group configuration with new annotations
        changes_made = reconcile_target_group(elbv2, target_group_arn, spec, new, region=spec.get('region'))
        if changes_made:
            logger.info(f"Successfully reconciled target group: {target_group_arn}")
            
            # Update status to reflect changes
            try:
                api = kubernetes.client.CustomObjectsApi()
                api.patch_namespaced_custom_object_status(
                    group="aws.k8s.io",
                    version="v1",
                    plural="awstargetgroups",
                    namespace=meta['namespace'],
                    name=meta['name'],
                    body={'status': {'targetGroupArn': target_group_arn, 'state': 'active'}}
                )
                logger.info(f"Successfully updated status for {meta['name']}")
            except Exception as e:
                logger.error(f"Failed to update status: {str(e)}", exc_info=True)
    except Exception as e:
        logger.error(f"Error reconciling target group: {str(e)}", exc_info=True)
        
        # Update status to reflect error
        try:
            api = kubernetes.client.CustomObjectsApi()
            api.patch_namespaced_custom_object_status(
                group="aws.k8s.io",
                version="v1",
                plural="awstargetgroups",
                namespace=meta['namespace'],
                name=meta['name'],
                body={'status': {'state': 'error', 'error': str(e)}}
            )
        except Exception as status_e:
            logger.error(f"Failed to update error status: {str(status_e)}", exc_info=True)
        
        raise kopf.PermanentError(f"Failed to reconcile target group: {str(e)}")