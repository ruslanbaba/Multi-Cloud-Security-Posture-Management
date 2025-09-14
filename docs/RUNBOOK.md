# Runbook

## Forwarder Failures
- Check Lambda/Cloud Function logs for errors.
- Review DLQs (SQS for AWS, Pub/Sub DLQ for GCP) for poisoned messages.
- Reprocess after remediation.

## High Volume Spikes
- Increase Lambda reserved concurrency and memory.
- For GCP, adjust min instances and memory in Cloud Functions.

## Token Rotation
- Update Secret Manager/Secrets Manager with new value; no redeploy required.

## Schema Changes
- Update mappers in `src/common/mappings.py`; add tests; deploy.
