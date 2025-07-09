# Default values for configuration
AWS_REGION ?= us-east-1
ECR_REPO_NAME ?= aws-targetgroup-controller
IMAGE_TAG ?= latest

# Get AWS account ID
AWS_ACCOUNT_ID := $(shell aws sts get-caller-identity --query Account --output text)
ECR_REPO_URL := $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
FULL_IMAGE_NAME := $(ECR_REPO_URL)/$(ECR_REPO_NAME):$(IMAGE_TAG)

.PHONY: help build deploy destroy clean

help: ## Display this help message
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@awk -F ':|##' '/^[^\t].+?:.*?##/ { printf "  %-20s %s\n", $$1, $$NF }' $(MAKEFILE_LIST)

build: ## Build and push the controller image to ECR
	@echo "=== Building and pushing image to ECR ==="
	@echo "Region: $(AWS_REGION)"
	@echo "Repository: $(ECR_REPO_NAME)"
	@echo "Tag: $(IMAGE_TAG)"
	
	@echo "Authenticating with ECR..."
	aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $(ECR_REPO_URL)
	
	@echo "Building Docker image..."
	docker build --platform linux/amd64 -t $(FULL_IMAGE_NAME) .
	
	@echo "Pushing image to ECR..."
	docker push $(FULL_IMAGE_NAME)
	
	@echo "=== Successfully built and pushed $(FULL_IMAGE_NAME) ==="

deploy: ## Deploy the controller to Kubernetes cluster
	@echo "=== Deploying AWS Target Group Controller ==="
	kubectl apply -f manifests/awstargetgroup-crd.yaml
	kubectl apply -f manifests/cert-manager.yaml
	kubectl apply -f manifests/cluster-info.yaml
	kubectl apply -f manifests/rbac.yaml
	kubectl apply -f manifests/webhook-configuration.yaml
	kubectl apply -f manifests/deployment.yaml
	@echo "=== Deployment complete ==="

destroy: ## Remove the controller and associated resources from the cluster
	@echo "=== Removing AWS Target Group Controller ==="
	-kubectl delete -f manifests/deployment.yaml
	-kubectl delete -f manifests/webhook-configuration.yaml
	-kubectl delete -f manifests/rbac.yaml
	-kubectl delete -f manifests/cluster-info.yaml
	-kubectl delete -f manifests/cert-manager.yaml
	-kubectl delete -f manifests/awstargetgroup-crd.yaml
	@echo "=== Removal complete ==="

clean: ## Clean up local Docker images
	-docker rmi $(FULL_IMAGE_NAME)