#!/usr/bin/env bash
# deploy-aws.sh
# One-shot deploy helper for AWS: creates/updates ECR repo, builds, pushes,
# then runs terraform apply for the ECS Fargate stack.
#
# Prereqs: aws cli configured, docker installed, terraform installed.
#
# Usage: ./scripts/deploy-aws.sh

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
PROJECT_NAME="aws-compliance-agent"

echo "▶ Getting AWS account ID..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_URL="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}"

echo "▶ Ensuring ECR repository exists..."
aws ecr describe-repositories --repository-names "${PROJECT_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${PROJECT_NAME}" --region "${AWS_REGION}" --image-scanning-configuration scanOnPush=true

echo "▶ Logging in to ECR..."
aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "▶ Building and pushing image..."
./scripts/build-and-push.sh "${ECR_URL}" latest

echo "▶ Running terraform apply..."
cd terraform
terraform init -upgrade
terraform plan -out=tfplan
echo ""
read -p "Apply this plan? (yes/no) " CONFIRM
if [[ "$CONFIRM" == "yes" ]]; then
  terraform apply tfplan
  echo "✓ Deployment complete."
  terraform output
else
  echo "Aborted. Run 'terraform apply tfplan' manually when ready."
fi
