# Architecture

This solution aggregates security findings from AWS Security Hub and Google Cloud SCC into Splunk HEC.

- AWS: EventBridge -> Lambda (this repo) -> Splunk HEC. DLQ via SQS. Token from Secrets Manager. Logs to CloudWatch.
- GCP: SCC Notification -> Pub/Sub -> Cloud Function Gen2 (this repo) -> Splunk HEC. DLQ on Pub/Sub subscription. Token from Secret Manager. Logs to Cloud Logging.

Security controls:
- Least-privilege IAM/service accounts
- KMS/CMK-backed secret storage
- TLS verification and minimum TLS 1.2
- Structured logging; sensitive fields not logged

Extensibility:
- `src/common/mappings.py` for mapping to Splunk CIM-like schema
- Terraform modules expose variables for customization
