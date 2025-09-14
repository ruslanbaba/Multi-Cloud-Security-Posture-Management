# Architecture

- AWS: Security Hub emits to EventBridge -> Lambda forwarder -> Splunk HEC
- GCP: SCC Notification -> Pub/Sub -> Cloud Function Gen2 forwarder -> Splunk HEC
- Secrets: AWS Secrets Manager or GCP Secret Manager for HEC token
- Reliability: DLQs (SQS on AWS; Pub/Sub retains/acks), structured logs, retries with backoff

Key flows align with least-privilege IAM and use TLS verification for egress.
