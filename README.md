# AWS Agentic Compliance Agent

A continuously-running compliance agent that evaluates your AWS environment against **FedRAMP Moderate**, **CIS AWS Foundations Benchmark**, **NIST 800-53**, **PCI DSS**, and custom org policies — then uses Claude to prioritize findings, generate remediation scripts, and produce executive-ready reports.

Tested end-to-end in this repo: dependency install, module wiring, and the HTML/JSON report pipeline all verified working.

## What's inside

```
src/
  agent.js                    Main orchestrator (CLI: scan / watch / report / test)
  server.js                   HTTP server (/healthz, /api/scan, /api/findings, /api/score)
  lambda.js                   AWS Lambda handler for serverless deployment
  aws/client.js                AWS SDK client factory + cross-account role assumption
  scanners/
    s3-scanner.js              S3 public access, encryption, logging, versioning
    iam-scanner.js              Password policy, root account, MFA, stale keys, wildcard policies
    ec2-scanner.js              Security groups, IMDSv2, EBS encryption, VPC flow logs
    rds-scanner.js              Encryption at rest, public access, Multi-AZ, deletion protection
    cloudtrail-kms-scanner.js  Multi-region trail, log validation, KMS key rotation
  utils/
    ai-remediation.js          Claude-powered risk prioritization, script generation, exec summaries
    remediator.js               Applies LOW-risk automated fixes (dry-run by default)
    notifier.js                  SNS + Slack alerting on critical findings
  reporters/report-generator.js HTML + JSON report generation

Dockerfile                    Production container image (any cloud)
docker-compose.yml            Local run / single-host deployment
k8s/deployment.yaml           Kubernetes manifests (EKS, GKE, AKS, self-managed)
terraform/main.tf             AWS ECS Fargate full IaC (cluster, IAM, secrets, SNS, ECR)
terraform/cross-account-role.yaml  CloudFormation role to deploy in each scanned account
scripts/build-and-push.sh     Build + push to any container registry
scripts/deploy-aws.sh         One-shot AWS deploy (ECR + Terraform)
```

## 1. Configure

```bash
cp .env.example .env
# Fill in ANTHROPIC_API_KEY at minimum.
# AWS credentials: leave blank to use IAM role / instance profile / EKS IRSA (recommended),
# or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY for local testing only.
```

## 2. Run locally

```bash
npm install
node src/agent.js --mode=test     # validates AWS credentials, no mutating calls
node src/agent.js --mode=scan     # one full scan + HTML/JSON report in ./reports
node src/agent.js --mode=watch    # continuous loop + HTTP server on :8080
```

Or with Docker Compose:

```bash
docker compose up --build
curl http://localhost:8080/healthz
curl -X POST http://localhost:8080/api/scan
```

## 3. Deploy — pick your platform

### AWS ECS Fargate (recommended for AWS-native shops)

```bash
./scripts/deploy-aws.sh
```
This builds the image, pushes to ECR, and runs the Terraform stack in `terraform/` — creating the ECS cluster, task/execution IAM roles (least-privilege, scoped read + remediation actions only), CloudWatch logs, an SNS alert topic, and Secrets Manager entry for your Anthropic key.

### AWS Lambda (serverless, lowest cost for periodic scans)

```bash
npm install --omit=dev
zip -r function.zip src node_modules package.json
aws lambda create-function \
  --function-name aws-compliance-agent \
  --runtime nodejs20.x \
  --handler src/lambda.handler \
  --zip-file fileb://function.zip \
  --timeout 300 --memory-size 1024 \
  --role arn:aws:iam::<ACCOUNT_ID>:role/ComplianceAgentLambdaRole
# Trigger hourly via EventBridge Scheduler:
aws scheduler create-schedule --name compliance-agent-hourly \
  --schedule-expression "rate(1 hour)" \
  --target "Arn=arn:aws:lambda:...:function:aws-compliance-agent,RoleArn=..." \
  --flexible-time-window "Mode=OFF"
```

### Kubernetes — EKS, GKE, AKS, or self-managed (cloud-agnostic)

```bash
./scripts/build-and-push.sh ghcr.io/your-org/aws-compliance-agent latest
kubectl apply -f k8s/deployment.yaml
kubectl -n security get pods -w
```
On EKS, the manifest uses IRSA (`eks.amazonaws.com/role-arn` annotation) so the pod assumes an IAM role without static keys. For GKE/AKS scanning AWS, swap that annotation for Workload Identity Federation, or fall back to a Kubernetes Secret with AWS keys for the task role.

### Any other container platform (Cloud Run, App Runner, Azure Container Apps, DigitalOcean)

The image is a standard OCI container exposing port 8080 with a `/healthz` endpoint — every major platform supports this directly:

```bash
./scripts/build-and-push.sh <your-registry>/aws-compliance-agent latest
# AWS App Runner
aws apprunner create-service --service-name aws-compliance-agent \
  --source-configuration ImageRepository="{ImageIdentifier=<image>,ImageRepositoryType=ECR}"
# Google Cloud Run
gcloud run deploy aws-compliance-agent --image <image> --port 8080
# Azure Container Apps
az containerapp create --name aws-compliance-agent --image <image> --target-port 8080
```

## 4. Cross-account scanning

To scan additional AWS accounts from one hub deployment, deploy the cross-account role in **each target account**:

```bash
aws cloudformation deploy \
  --template-file terraform/cross-account-role.yaml \
  --stack-name compliance-agent-role \
  --parameter-overrides HubAccountId=<HUB_ACCOUNT_ID> \
  --capabilities CAPABILITY_NAMED_IAM
```
Then set `AWS_TARGET_ACCOUNTS=111111111111,222222222222` in the hub's environment.

## 5. Reports

Every scan produces:
- **HTML report** — executive summary, compliance score, findings by service/framework, expandable remediation steps. Open directly or serve from `/` on the HTTP server.
- **JSON report** — full machine-readable findings for ingestion into a SIEM, ticketing system, or BI dashboard.

Critical findings automatically trigger SNS and/or Slack alerts if configured.

## Safety model

- All scanners are **read-only** by design.
- The remediator only acts on findings explicitly marked `automated: true, risk: 'LOW'`.
- `REMEDIATION_MODE=DRY_RUN` (default) logs the action without calling mutating AWS APIs — switch to `ACTIVE` only after reviewing dry-run output.
- IAM/CloudFormation roles in this repo grant exactly the actions the remediator code calls — nothing broader.
