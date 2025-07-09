# AWS Target Group Annotations

This document describes all the available annotations that can be used with the AWS Target Group resource.

## Health Check Annotations

Health check annotations allow you to configure the target group's health check settings. All health check annotations use the prefix `aws.k8s.io.targetGroup/healthCheck.`.

| Annotation | Description | Type | Required | Example |
|------------|-------------|------|----------|---------|
| `aws.k8s.io.targetGroup/healthCheck.enabled` | Enable or disable health checks | boolean | Yes (for health checks) | `"true"` |
| `aws.k8s.io.targetGroup/healthCheck.protocol` | Protocol to use for health checks | string | No | `"HTTP"` |
| `aws.k8s.io.targetGroup/healthCheck.port` | Port to use for health checks | string | No | `"8080"` |
| `aws.k8s.io.targetGroup/healthCheck.path` | Path for HTTP/HTTPS health checks | string | Yes (for HTTP/HTTPS) | `"/health"` |
| `aws.k8s.io.targetGroup/healthCheck.healthyThresholdCount` | Number of consecutive successful health checks | integer | No | `"3"` |
| `aws.k8s.io.targetGroup/healthCheck.unhealthyThresholdCount` | Number of consecutive failed health checks | integer | No | `"3"` |
| `aws.k8s.io.targetGroup/healthCheck.intervalSeconds` | Interval between health checks in seconds | integer | No | `"30"` |
| `aws.k8s.io.targetGroup/healthCheck.timeoutSeconds` | Health check timeout in seconds | integer | No | `"5"` |

## Target Group Attributes

Target group attributes can be set using annotations with the prefix `aws.k8s.io.targetGroup/attribute.`. These map directly to AWS Target Group attributes.

| Annotation | Description | Example |
|------------|-------------|---------|
| `aws.k8s.io.targetGroup/attribute.deregistration_delay.timeout_seconds` | Connection draining timeout | `"300"` |
| `aws.k8s.io.targetGroup/attribute.stickiness.enabled` | Enable sticky sessions | `"true"` |
| `aws.k8s.io.targetGroup/attribute.stickiness.type` | Type of sticky sessions | `"lb_cookie"` |
| `aws.k8s.io.targetGroup/attribute.stickiness.duration_seconds` | Sticky session duration | `"86400"` |
| `aws.k8s.io.targetGroup/attribute.load_balancing.algorithm.type` | Load balancing algorithm | `"round_robin"` |

## Tags

Tags can be added to the target group using annotations with the prefix `aws.k8s.io.targetGroup/tag.`.

| Annotation | Description | Example |
|------------|-------------|---------|
| `aws.k8s.io.targetGroup/tag.Environment` | Sets an Environment tag | `"production"` |
| `aws.k8s.io.targetGroup/tag.Team` | Sets a Team tag | `"platform"` |

## Load Balancer Listener Annotations

These annotations configure the load balancer listener settings for the target group.

| Annotation | Description | Required | Example |
|------------|-------------|----------|---------|
| `aws.k8s.io.loadBalancer/listener.port` | Port for the listener | Yes | `"443"` |
| `aws.k8s.io.loadBalancer/listener.protocol` | Protocol for the listener | Yes | `"HTTPS"` |
| `aws.k8s.io.loadBalancer/listener.priority` | Rule priority for the listener | Yes | `"100"` |
| `aws.k8s.io.loadBalancer/listener.certificateArn` | Certificate ARN for HTTPS/TLS listeners | Yes (for HTTPS/TLS) | `"arn:aws:acm:..."` |

### Listener Conditions

For Application Load Balancers (ALB), you can configure multiple listener rule conditions using indexed annotations:

| Annotation | Description | Example |
|------------|-------------|---------|
| `aws.k8s.io.loadBalancer/listener.condition.0.field` | First condition field | `"path-pattern"` |
| `aws.k8s.io.loadBalancer/listener.condition.0.values` | First condition values (comma-separated) | `"/api/*,/v1/*"` |
| `aws.k8s.io.loadBalancer/listener.condition.1.field` | Second condition field | `"host-header"` |
| `aws.k8s.io.loadBalancer/listener.condition.1.values` | Second condition values (comma-separated) | `"api.example.com"` |

## Example Usage

```yaml
apiVersion: aws.k8s.io/v1
kind: AWSTargetGroup
metadata:
  name: my-target-group
  annotations:
    # Health Check Configuration
    aws.k8s.io.targetGroup/healthCheck.enabled: "true"
    aws.k8s.io.targetGroup/healthCheck.protocol: "HTTP"
    aws.k8s.io.targetGroup/healthCheck.port: "8080"
    aws.k8s.io.targetGroup/healthCheck.path: "/health"
    aws.k8s.io.targetGroup/healthCheck.healthyThresholdCount: "3"
    aws.k8s.io.targetGroup/healthCheck.intervalSeconds: "30"
    
    # Target Group Attributes
    aws.k8s.io.targetGroup/attribute.deregistration_delay.timeout_seconds: "30"
    aws.k8s.io.targetGroup/attribute.stickiness.enabled: "true"
    aws.k8s.io.targetGroup/attribute.stickiness.type: "lb_cookie"
    
    # Tags
    aws.k8s.io.targetGroup/tag.Environment: "production"
    
    # Listener Configuration
    aws.k8s.io.loadBalancer/listener.port: "443"
    aws.k8s.io.loadBalancer/listener.protocol: "HTTPS"
    aws.k8s.io.loadBalancer/listener.priority: "100"
    aws.k8s.io.loadBalancer/listener.certificateArn: "arn:aws:acm:region:account:certificate/certificate-id"
    aws.k8s.io.loadBalancer/listener.condition.0.field: "path-pattern"
    aws.k8s.io.loadBalancer/listener.condition.0.values: "/api/*"
spec:
  targetType: ip
  port: 8080
  protocol: HTTP
  vpcId: vpc-12345
  region: us-west-2
  serviceRef:
    name: my-service
    port: 8080
  loadBalancerRef:
    name: my-load-balancer
```