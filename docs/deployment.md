# Deployment Guide

Prereqs: AWS account with Security Hub, GCP project with SCC enabled, Splunk HEC endpoint and token stored in secret managers.

## AWS

- Create a secret in AWS Secrets Manager for the HEC token and supply its ARN to the module variable `splunk_hec_token_secret_arn`.
- Apply the Terraform in `infra/terraform/envs/<env>` after configuring providers and variables.

## GCP

- Create a secret in Secret Manager with the HEC token; set env `GCP_SECRET_MANAGER_HEC_TOKEN` on the Cloud Function to `projects/<id>/secrets/<name>/versions/latest`.
- Wire SCC NotificationConfig to the Pub/Sub topic created by the module (update organization id as applicable).

## Splunk

- Ensure the HEC token has index permissions for `splunk_index` if specified.
- Confirm source/sourcetype mapping in Splunk CIM as needed.
