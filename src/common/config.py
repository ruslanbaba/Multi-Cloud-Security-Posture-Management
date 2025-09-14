from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional

# Optional imports for cloud secret managers
try:  # pragma: no cover - optional in local unit tests
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore

try:  # pragma: no cover
    from google.cloud import secretmanager as gcp_sm  # type: ignore
except Exception:  # pragma: no cover
    gcp_sm = None  # type: ignore


@dataclass(frozen=True)
class SplunkConfig:
    hec_url: str
    hec_token: str
    hec_source: str = "mcspm"
    hec_sourcetype: str = "mcspm:finding"
    hec_index: Optional[str] = None
    verify_tls: bool = True


def load_splunk_from_env(prefix: str = "SPLUNK_") -> SplunkConfig:
    url = os.getenv(f"{prefix}HEC_URL", "")
    token = os.getenv(f"{prefix}HEC_TOKEN", "")
    source = os.getenv(f"{prefix}SOURCE", "mcspm")
    sourcetype = os.getenv(f"{prefix}SOURCETYPE", "mcspm:finding")
    index = os.getenv(f"{prefix}INDEX")
    verify_tls_str = os.getenv(f"{prefix}VERIFY_TLS", "true").lower()
    verify_tls = verify_tls_str in ("1", "true", "yes")

    if not url:
        raise ValueError("SPLUNK_HEC_URL is required")

    if not token:
        # Attempt cloud secret manager resolution
        # AWS: provide env AWS_SECRETS_MANAGER_HEC_TOKEN_ARN
        aws_secret_arn = os.getenv("AWS_SECRETS_MANAGER_HEC_TOKEN_ARN")
        if aws_secret_arn and boto3 is not None:
            try:  # pragma: no cover
                sm = boto3.client("secretsmanager")
                resp = sm.get_secret_value(SecretId=aws_secret_arn)
                token = resp.get("SecretString") or token
            except Exception:
                pass
        # GCP: provide env GCP_SECRET_MANAGER_HEC_TOKEN (projects/<id>/secrets/<name>/versions/<ver> or latest)
        if not token:
            gcp_secret_res = os.getenv("GCP_SECRET_MANAGER_HEC_TOKEN")
            if gcp_secret_res and gcp_sm is not None:
                try:  # pragma: no cover
                    client = gcp_sm.SecretManagerServiceClient()
                    resp = client.access_secret_version(name=gcp_secret_res)
                    token = resp.payload.data.decode("utf-8")
                except Exception:
                    pass

    if not token:
        raise ValueError("SPLUNK_HEC_TOKEN is required (or set AWS/GCP secret env references)")

    return SplunkConfig(
        hec_url=url,
        hec_token=token,
        hec_source=source,
        hec_sourcetype=sourcetype,
        hec_index=index,
        verify_tls=verify_tls,
    )
