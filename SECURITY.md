# Security Policy

We take the security of this project seriously. Please follow the guidance below when reporting vulnerabilities or handling sensitive information.

- Do not include secrets or credentials in code, examples, or issues.
- Report suspected vulnerabilities privately via your organization's disclosure process.
- Use dedicated secret stores (AWS Secrets Manager, GCP Secret Manager) with KMS-managed encryption keys.
- Enforce least-privilege IAM roles and scoped service accounts for all deployable units.
- Enable audit logging and retain logs per your compliance requirements.

## Supported Versions

Security fixes are applied to the `main` branch. Consumers should pin releases with changelogs.

## Reporting a Vulnerability

- Provide a clear description, steps to reproduce, and potential impact.
- Share only the minimum details required to triage.
- We will acknowledge receipt and provide a remediation timeline where possible.

## Cryptographic Practices

- TLS 1.2+ required for all egress to Splunk HEC or other endpoints.
- KMS customer-managed keys for Secrets Manager and at-rest encryption.
- Do not disable certificate validation.

## Supply Chain Security

- Dependencies are pinned (hash/versions) and scanned in CI.
- Terraform providers pinned with version constraints.
- Use CodeQL and container scanning.

## Hardening Defaults

- Logging with redaction of sensitive fields.
- Dead-letter queues for asynchronous processing.
- Minimum privileges for event sources and runtime identities.