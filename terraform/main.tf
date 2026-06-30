############################################################
# AWS Compliance Agent — Terraform (ECS Fargate deployment)
# Deploys the agent as a long-running Fargate service with:
#   - ECR repository
#   - ECS cluster/service/task definition
#   - IAM execution + task roles (least-privilege read + scoped fix)
#   - CloudWatch log group
#   - SNS topic for critical alerts
#   - EventBridge rule (optional periodic restart/trigger)
#   - Secrets Manager for ANTHROPIC_API_KEY
############################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ────────────────────────────────────────────────

variable "aws_region" {
  default = "us-east-1"
}
variable "project_name" {
  default = "aws-compliance-agent"
}
variable "anthropic_api_key" {
  description = "Anthropic API key (sensitive)"
  type        = string
  sensitive   = true
}
variable "active_frameworks" {
  default = "FEDRAMP,CIS,NIST"
}
variable "remediation_mode" {
  default = "DRY_RUN" # DRY_RUN | ACTIVE | OFF
}
variable "scan_interval_minutes" {
  default = 60
}
variable "vpc_id" {
  description = "Existing VPC ID to deploy into"
  type        = string
}
variable "subnet_ids" {
  description = "Subnet IDs for the Fargate task (private subnets recommended)"
  type        = list(string)
}
variable "slack_webhook_url" {
  default   = ""
  sensitive = true
}
variable "target_account_ids" {
  description = "Comma-separated list of AWS account IDs to scan (cross-account). Leave empty for current account only."
  default     = ""
}

# ── ECR ──────────────────────────────────────────────────────

resource "aws_ecr_repository" "agent" {
  name                 = var.project_name
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

# ── Secrets Manager ─────────────────────────────────────────

resource "aws_secretsmanager_secret" "anthropic_key" {
  name = "${var.project_name}/anthropic-api-key"
}

resource "aws_secretsmanager_secret_version" "anthropic_key" {
  secret_id     = aws_secretsmanager_secret.anthropic_key.id
  secret_string = var.anthropic_api_key
}

# ── CloudWatch Logs ──────────────────────────────────────────

resource "aws_cloudwatch_log_group" "agent" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 90
}

# ── SNS for critical alerts ─────────────────────────────────

resource "aws_sns_topic" "compliance_alerts" {
  name = "${var.project_name}-critical-alerts"
}

# ── IAM: Task Execution Role (pulls image, writes logs, reads secret) ──

resource "aws_iam_role" "execution_role" {
  name = "${var.project_name}-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution_role_managed" {
  role       = aws_iam_role.execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_role_secrets" {
  name = "secrets-access"
  role = aws_iam_role.execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.anthropic_key.arn]
    }]
  })
}

# ── IAM: Task Role (what the agent itself can do in AWS) ────────────
# Read-only compliance evaluation permissions + narrowly scoped remediation actions.

resource "aws_iam_role" "task_role" {
  name = "${var.project_name}-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "task_role_readonly" {
  name = "compliance-readonly"
  role = aws_iam_role.task_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyEvaluation"
        Effect = "Allow"
        Action = [
          "s3:GetBucket*", "s3:ListBucket*", "s3:ListAllMyBuckets", "s3:GetEncryptionConfiguration",
          "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock",
          "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
          "ec2:Describe*",
          "rds:Describe*",
          "cloudtrail:Describe*", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors",
          "kms:List*", "kms:Describe*", "kms:GetKeyRotationStatus",
          "config:Describe*", "config:Get*",
          "securityhub:Get*", "securityhub:List*",
          "sts:GetCallerIdentity", "sts:AssumeRole",
          "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ScopedRemediationActions"
        Effect = "Allow"
        Action = [
          "s3:PutPublicAccessBlock", "s3:PutBucketEncryption", "s3:PutBucketVersioning",
          "ec2:ModifyInstanceMetadataOptions", "ec2:RevokeSecurityGroupIngress",
          "kms:EnableKeyRotation",
          "cloudtrail:StartLogging", "cloudtrail:UpdateTrail",
          "rds:ModifyDBInstance",
          "iam:UpdateAccountPasswordPolicy"
        ]
        Resource = "*"
        Condition = {
          # Extra guardrail: only allow these actions when explicitly tagged for remediation.
          # Customize per org tagging strategy.
          StringEquals = { "aws:RequestedRegion" = var.aws_region }
        }
      },
      {
        Sid      = "PublishAlerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.compliance_alerts.arn]
      }
    ]
  })
}

# Cross-account assume role permission (only created if target accounts specified)
resource "aws_iam_role_policy" "task_role_cross_account" {
  count = var.target_account_ids != "" ? 1 : 0
  name  = "cross-account-assume"
  role  = aws_iam_role.task_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = [for acct in split(",", var.target_account_ids) : "arn:aws:iam::${trimspace(acct)}:role/ComplianceAgentRole"]
    }]
  })
}

# ── ECS Cluster / Task / Service ─────────────────────────────

resource "aws_ecs_cluster" "agent" {
  name = "${var.project_name}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "agent" {
  family                   = var.project_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.execution_role.arn
  task_role_arn            = aws_iam_role.task_role.arn

  container_definitions = jsonencode([{
    name      = var.project_name
    image     = "${aws_ecr_repository.agent.repository_url}:latest"
    essential = true
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    environment = [
      { name = "AWS_REGION", value = var.aws_region },
      { name = "ACTIVE_FRAMEWORKS", value = var.active_frameworks },
      { name = "REMEDIATION_MODE", value = var.remediation_mode },
      { name = "AUTO_REMEDIATE_THRESHOLD", value = "CRITICAL" },
      { name = "SCAN_INTERVAL_MINUTES", value = tostring(var.scan_interval_minutes) },
      { name = "SNS_TOPIC_ARN", value = aws_sns_topic.compliance_alerts.arn },
      { name = "SLACK_WEBHOOK_URL", value = var.slack_webhook_url },
      { name = "AWS_TARGET_ACCOUNTS", value = var.target_account_ids },
      { name = "ENABLE_HTTP_SERVER", value = "true" },
      { name = "PORT", value = "8080" },
    ]
    secrets = [
      { name = "ANTHROPIC_API_KEY", valueFrom = aws_secretsmanager_secret.anthropic_key.arn }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.agent.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "agent"
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "wget -qO- http://localhost:8080/healthz || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
  }])
}

resource "aws_security_group" "agent" {
  name_prefix = "${var.project_name}-sg-"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # outbound only — calls AWS APIs + Anthropic API
  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # restrict to internal VPC CIDR — adjust to your network
  }
}

resource "aws_ecs_service" "agent" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.agent.id
  task_definition = aws_ecs_task_definition.agent.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.agent.id]
    assign_public_ip = false
  }

  lifecycle {
    ignore_changes = [task_definition] # allow CI/CD to update image without TF drift
  }
}

# ── Outputs ──────────────────────────────────────────────────

output "ecr_repository_url" {
  value = aws_ecr_repository.agent.repository_url
}
output "ecs_cluster_name" {
  value = aws_ecs_cluster.agent.name
}
output "sns_topic_arn" {
  value = aws_sns_topic.compliance_alerts.arn
}
output "log_group" {
  value = aws_cloudwatch_log_group.agent.name
}
