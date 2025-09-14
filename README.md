# Multi-Cloud Security Posture Management (AWS + GCP → Splunk)

Enterprise-ready blueprint to aggregate security findings from AWS Security Hub and Google Cloud Security Command Center (SCC) into Splunk via managed, hardened serverless forwarders and infrastructure-as-code.

## Highlights

- Unified ingestion: AWS Security Hub and GCP SCC → Splunk HEC
- Cloud-native transports: EventBridge, Lambda, SQS DLQ (AWS); SCC Notifications, Pub/Sub, Cloud Functions Gen2 (GCP)
- Secure by default: Secrets in Secret Managers, KMS encryption, least-privilege IAM, TLS verification
- IaC modules: Terraform modules for AWS and GCP with opinionated defaults
- Extensible mappings: Shared Python library maps cloud findings to Splunk CIM-like fields
- CI and quality: Linting, typing, unit tests, terraform fmt/validate, security policy

## Repository Layout

```
infra/
  terraform/
    modules/
      aws/          # AWS Lambda, EventBridge, Security Hub, KMS, VPC support
      gcp/          # GCP Pub/Sub, SCC, Cloud Functions Gen2, Secret Manager
    envs/
      staging/      # Environment-specific compositions
      prod/
src/
  common/           # Shared libraries (HEC client, mappings, config)
  aws_lambda_forwarder/
  gcp_function_forwarder/
tests/              # Unit tests with mocked dependencies
docs/               # Architecture, deployment, VPC, advanced security
splunk/             # Sample dashboard and saved searches
.github/workflows/  # CI: lint, test, terraform validate, CodeQL
```

## Enhanced Features

- **VPC Support**: Optional private networking for Lambda and Cloud Functions
- **KMS Integration**: Customer-managed keys for encryption at rest and in transit
- **IAM Boundaries**: Permission boundaries and organization policies
- **Enhanced Mappings**: Rich CIM-like field mapping with metadata enrichment
- **Splunk Assets**: Ready-to-use dashboard and saved searches
- **Security Controls**: Audit logging, compliance frameworks, runtime verificationSee `docs/` for architecture, deployment, and runbooks.

## Status

This is a framework-style template intended to be adapted per environment. No credentials are included; all secrets provided via cloud secret managers at deploy time.
