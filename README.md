# AWS Target Group Controller

This Kubernetes controller automates the management of AWS Target Groups by providing a seamless integration between Kubernetes and AWS Elastic Load Balancing. This is a helper tool for [AWS load balancer controller](https://github.com/kubernetes-sigs/aws-load-balancer-controller) to reduce the gap between targetGroupBinding and targetGroup and listener configurations. It enables declarative configuration of AWS Target Groups using Custom Resource Definitions (CRDs), supports both Application Load Balancers (ALB) and Network Load Balancers (NLB), and includes a mutation webhook for automatic label management. The controller handles the complete lifecycle of target groups, including creation, updates, and deletion, while maintaining synchronization between Kubernetes services and AWS load balancer targets through TargetGroupBinding resources.

## Prerequisites

1. Kubernetes cluster
2. cert-manager installed in the cluster
3. AWS credentials with permissions to manage Target Groups
4. Docker for building the controller image

## Installation

1. First, install cert-manager if not already installed:
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
```

2. Build and deploy the controller:

The project includes a Makefile with the following targets:
- `make build`: Build and push the controller image to ECR
- `make deploy`: Deploy the controller to your Kubernetes cluster
- `make destroy`: Remove the controller and associated resources
- `make clean`: Clean up local Docker images
- `make help`: Display help information about available targets

You can configure the build process using the following environment variables:
```bash
# Set your AWS region (optional, defaults to us-east-1)
export AWS_REGION=us-east-1

# Set your ECR repository name (optional, defaults to aws-targetgroup-controller)
export ECR_REPO_NAME=aws-targetgroup-controller

# Set the image tag (optional, defaults to latest)
export IMAGE_TAG=latest
```

To build and deploy:
```bash
# Build and push the controller image
make build

# Deploy the controller to your cluster
make deploy
```

To remove the controller:
```bash
# Remove all controller resources from the cluster
make destroy
```

## Usage

### Basic Usage

Create an AWSTargetGroup resource:

```yaml
apiVersion: aws.k8s.io/v1
kind: AWSTargetGroup
metadata:
  name: sample-target-group
spec:
  targetType: instance
  port: 80
  protocol: HTTP
  vpcId: vpc-12345678
```

The controller will create the target group in AWS and the mutation webhook will add default labels.

For a complete reference of all available annotations and their usage, please see [annotations.md](annotations.md).

### End-to-End Examples

Here's a complete walkthrough of setting up and using the AWS Target Group Controller:

1. **Create a Kubernetes Service**

First, create the service that will be the target for your load balancer:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  selector:
    app: my-app
  ports:
    - port: 80
      targetPort: 8080
  type: ClusterIP
```

2. **Create an AWSTargetGroup with Advanced Configuration**

Create a target group with health checks, attributes, and load balancer configuration:

```yaml
apiVersion: aws.k8s.io/v1
kind: AWSTargetGroup
metadata:
  name: sample-target-group
  annotations:
    # Health Check Configuration
    aws.k8s.io.targetGroup/healthCheck.enabled: "true"
    aws.k8s.io.targetGroup/healthCheck.path: "/health"
    aws.k8s.io.targetGroup/healthCheck.port: "traffic-port"
    aws.k8s.io.targetGroup/healthCheck.protocol: "HTTP"
    aws.k8s.io.targetGroup/healthCheck.HealthCheckIntervalSeconds: "30"
    
    # Target Group Attributes
    aws.k8s.io.targetGroup/attribute.deregistration_delay.timeout_seconds: "300"
    aws.k8s.io.targetGroup/attribute.stickiness.enabled: "true"
    aws.k8s.io.targetGroup/attribute.stickiness.type: "lb_cookie"
    
    # Load Balancer Configuration
    aws.k8s.io.loadBalancer/listener.port: "443"
    aws.k8s.io.loadBalancer/listener.protocol: "HTTPS"
    aws.k8s.io.loadBalancer/listener.priority: "100"
spec:
  targetType: instance
  port: 80
  protocol: HTTP
  vpcId: vpc-12345678
  serviceRef:
    name: my-service
    port: 80
  loadBalancerRef:
    name: my-application-lb
```


3. **Verify the Setup**

Check the status of your resources:

```bash
# Check the AWSTargetGroup status
kubectl get awstargetgroup sample-target-group -o yaml

# Check the TargetGroupBinding status
kubectl get targetgroupbinding sample-target-group-binding -o yaml

# Verify the target group in AWS
aws elbv2 describe-target-groups \
  --names sample-target-group

# Check target health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:region:account-id:targetgroup/sample-target-group/1234567890
```

5. **Cleanup**

To remove the resources:

```bash

# Delete the AWSTargetGroup (this will also delete the AWS target group)
kubectl delete awstargetgroup sample-target-group

# Delete the service
kubectl delete service my-service
```

The controller will handle:
- Creating the target group in AWS with specified configuration
- Adding default labels via the mutation webhook
- Managing the lifecycle of the AWS target group
- Cleaning up AWS resources when the CRD is deleted
- Maintaining the binding between the Kubernetes service and AWS target group

## Configuration

The controller can be configured using command line arguments:

Command Line Arguments:
- `--periodic-check-interval`: Interval in seconds for checking AWS target groups (default: 5)

## Features

- Manages AWS Target Groups lifecycle
- Mutation webhook for default labels
- SSL/TLS managed by cert-manager
- Automatic cleanup of AWS resources when CRD is deleted

## Architecture

The controller consists of two main components:
1. Kopf-based controller that manages AWS Target Groups
2. Flask-based mutation webhook that adds default labels

Both components run in the same pod but as separate containers, with the webhook using cert-manager for SSL/TLS certificate management.