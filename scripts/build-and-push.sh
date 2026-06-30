#!/usr/bin/env bash
# build-and-push.sh
# Builds the Docker image and pushes it to whichever registry you point it at:
# AWS ECR, Google Artifact Registry, Azure ACR, Docker Hub, GitHub Container Registry, etc.
#
# Usage:
#   ./scripts/build-and-push.sh <registry-url> [tag]
#
# Examples:
#   ./scripts/build-and-push.sh 123456789012.dkr.ecr.us-east-1.amazonaws.com/aws-compliance-agent latest
#   ./scripts/build-and-push.sh ghcr.io/your-org/aws-compliance-agent v1.0.0
#   ./scripts/build-and-push.sh us-docker.pkg.dev/your-project/repo/aws-compliance-agent latest

set -euo pipefail

REGISTRY_URL="${1:-}"
TAG="${2:-latest}"

if [[ -z "$REGISTRY_URL" ]]; then
  echo "Usage: $0 <registry-url> [tag]"
  exit 1
fi

IMAGE="${REGISTRY_URL}:${TAG}"

echo "▶ Building image: ${IMAGE}"
docker build -t "${IMAGE}" .

echo "▶ Pushing image: ${IMAGE}"
docker push "${IMAGE}"

echo "✓ Done. Image available at: ${IMAGE}"
echo ""
echo "Next steps:"
echo "  ECS:        update terraform.tfvars image reference or run terraform apply"
echo "  Kubernetes: kubectl set image deployment/aws-compliance-agent compliance-agent=${IMAGE} -n security"
echo "  App Runner: aws apprunner update-service --service-arn <ARN> --source-configuration ImageRepository={ImageIdentifier=${IMAGE}}"
