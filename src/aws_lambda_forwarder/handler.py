from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from common.config import load_splunk_from_env, SplunkConfig
from common.hec import HECClient
from common.mappings import map_aws_security_hub_finding


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _load_cfg_with_optional_secret() -> SplunkConfig:
    import os
    import json
    import boto3  # available by default in AWS Lambda runtime

    secret_arn = os.getenv("AWS_SECRETS_MANAGER_HEC_TOKEN_ARN")
    if not secret_arn:
        return load_splunk_from_env()

    # Load base config from env except token
    cfg = load_splunk_from_env()
    sm = boto3.client("secretsmanager")
    resp = sm.get_secret_value(SecretId=secret_arn)
    token = resp.get("SecretString")
    if token:
        return SplunkConfig(
            hec_url=cfg.hec_url,
            hec_token=token,
            hec_source=cfg.hec_source,
            hec_sourcetype=cfg.hec_sourcetype,
            hec_index=cfg.hec_index,
            verify_tls=cfg.verify_tls,
        )
    raise RuntimeError("Secret did not contain a SecretString token")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    # EventBridge delivers events; Security Hub findings are in detail.findings
    logger.info("Received event with keys: %s", list(event.keys()))
    detail = event.get("detail", {})
    findings: List[Dict[str, Any]] = detail.get("findings", [])

    if not findings:
        logger.info("No findings in event; nothing to send")
        return {"status": "noop"}

    cfg = _load_cfg_with_optional_secret()
    client = HECClient(cfg)

    mapped = [map_aws_security_hub_finding(f) for f in findings]
    client.send_events(mapped)
    logger.info("Forwarded %d findings to Splunk", len(mapped))
    return {"status": "ok", "forwarded": len(mapped)}
