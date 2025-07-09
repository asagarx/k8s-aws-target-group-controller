#!/bin/bash

# Exit on error
set -e

# Configuration
AWS_REGION=${AWS_REGION:-"us-east-1"}  # Default region if not set
ECR_REPO_NAME=${ECR_REPO_NAME:-"aws-targetgroup-controller"}  # Default repository name
IMAGE_TAG=${IMAGE_TAG:-"latest"}  # Default tag

# Check if AWS credentials are available
# if [ -z "${AWS_ACCESS_KEY_ID}" ] || [ -z "${AWS_SECRET_ACCESS_KEY}" ]; then
#     echo "Error: AWS credentials not found. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
#     exit 1
# fi

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
if [ $? -ne 0 ]; then
    echo "Error: Failed to get AWS account ID. Please check your AWS credentials."
    exit 1
fi

# ECR repository URL
ECR_REPO_URL="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
FULL_IMAGE_NAME="${ECR_REPO_URL}/${ECR_REPO_NAME}:${IMAGE_TAG}"

echo "=== Building and pushing image to ECR ==="
echo "Region: ${AWS_REGION}"
echo "Repository: ${ECR_REPO_NAME}"
echo "Tag: ${IMAGE_TAG}"

# Authenticate Docker to ECR
echo "Authenticating with ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REPO_URL}

# # Create ECR repository if it doesn't exist
# echo "Ensuring ECR repository exists..."
# aws ecr describe-repositories --repository-names ${ECR_REPO_NAME} --region ${AWS_REGION} || \
#     aws ecr create-repository --repository-name ${ECR_REPO_NAME} --region ${AWS_REGION}

# Build Docker image
echo "Building Docker image..."
docker build --platform linux/amd64 -t ${FULL_IMAGE_NAME} .

# Push to ECR
echo "Pushing image to ECR..."
docker push ${FULL_IMAGE_NAME}

echo "=== Successfully built and pushed ${FULL_IMAGE_NAME} ==="