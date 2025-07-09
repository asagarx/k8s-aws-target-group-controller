import boto3
from botocore.config import Config
from functools import lru_cache
import logging
import time
import os
from botocore.exceptions import ClientError

# Constants
AWS_RETRY_ATTEMPTS = 3
AWS_RETRY_DELAY = 1  # seconds

# Configure AWS client with retries
aws_config = Config(
    retries=dict(
        max_attempts=AWS_RETRY_ATTEMPTS
    )
)

# Configure to use regional STS endpoints for IRSA
if os.environ.get('AWS_DEFAULT_REGION'):
    os.environ['AWS_STS_REGIONAL_ENDPOINTS'] = 'regional'

logger = logging.getLogger(__name__)

def get_credentials():
    """Get AWS credentials using the credential chain.
    
    The chain will try:
    1. IRSA (IAM Roles for Service Accounts)
    2. EC2 Instance Profile (Node IAM Role)
    3. Environment variables
    4. Shared credentials file
    
    Returns:
        dict: AWS credentials if found, None otherwise
    """
    try:
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is None:
            logger.warning("No AWS credentials found in the credential chain")
            return None
        return credentials
    except Exception as e:
        logger.error(f"Error getting AWS credentials: {str(e)}")
        return None

# @lru_cache(maxsize=None)
def get_elbv2_client(region=None):
    """Get cached AWS ELBv2 client with retry configuration.
    
    Args:
        region (str, optional): AWS region to use. If not provided, uses default region.
    
    Returns:
        boto3.client: AWS ELBv2 client
    
    Raises:
        botocore.exceptions.NoCredentialsError: If no credentials are found
    """
    client_kwargs = {'config': aws_config}
    
    # Use specified region or fall back to environment variable
    if region:
        client_kwargs['region_name'] = region
    elif os.environ.get('AWS_DEFAULT_REGION'):
        client_kwargs['region_name'] = os.environ.get('AWS_DEFAULT_REGION')
    
    # Get credentials using chain
    credentials = get_credentials()
    if credentials:
        client_kwargs['aws_access_key_id'] = credentials.access_key
        client_kwargs['aws_secret_access_key'] = credentials.secret_key
        if credentials.token:
            client_kwargs['aws_session_token'] = credentials.token
    
    return boto3.client('elbv2', **client_kwargs)

def retry_aws_operation(operation_func, *args, **kwargs):
    """
    Retry an AWS operation with exponential backoff.
    Returns the result of the operation or raises the last exception.
    """
    for attempt in range(AWS_RETRY_ATTEMPTS):
        try:
            return operation_func(*args, **kwargs)
        except ClientError as e:
            if attempt == AWS_RETRY_ATTEMPTS - 1:
                raise
            wait_time = (2 ** attempt) * AWS_RETRY_DELAY
            logger.warning(f"AWS operation failed, retrying in {wait_time}s: {str(e)}")
            time.sleep(wait_time)