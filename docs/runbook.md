# Operations Runbook

## Monitoring

- AWS Lambda: CloudWatch metrics and logs; alert on errors and DLQ depth.
- GCP Function: Cloud Logging; alert on error counts and Pub/Sub backlog.
- Splunk: monitor HEC health and ingestion latency.

## Common Issues

- 4xx from HEC: invalid token or index permissions.
- 5xx from HEC: transient; rely on retry and increase backoff.
- Missing findings: check EventBridge rule or SCC NotificationConfig bindings.
- TLS errors: verify CA trust and do not disable TLS verification.

## Maintenance

- Rotate HEC tokens in secret managers; no redeploy needed if environment references remain constant.
- Review IAM roles quarterly; apply least privilege.
