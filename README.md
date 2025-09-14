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
			aws/
			gcp/
		envs/
			staging/
			prod/
src/
	common/
	aws_lambda_forwarder/
	gcp_function_forwarder/
tests/
.github/workflows/
docs/
```

See `docs/` for architecture, deployment, and runbooks.

## Status

This is a framework-style template intended to be adapted per environment. No credentials are included; all secrets provided via cloud secret managers at deploy time.
