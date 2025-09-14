# Deployment Guide

Prerequisites:
- Splunk HEC endpoint URL and token stored in cloud secret managers
- AWS and GCP credentials with permissions to deploy the resources

Steps:
1. Review and customize variables in `infra/terraform/envs/{staging,prod}`.
2. Initialize and validate Terraform (no backend configured here).
3. Apply modules in your environment with your backend/workspace settings.

Post-deploy:
- Verify EventBridge rules (AWS) and NotificationConfig (GCP) are delivering findings.
- Confirm Lambda/Function logs contain forwarding confirmations and no secret values.
- Monitor DLQs and set alerts.

Security:
- Rotate HEC tokens regularly.
- Scope IAM/service accounts minimally.
- Use organization-level SCC notifications if applicable.
