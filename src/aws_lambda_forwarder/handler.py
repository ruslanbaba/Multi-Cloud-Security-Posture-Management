from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from common.config import load_splunk_from_env
from common.hec import HECClient
from common.mappings import map_aws_security_hub_finding


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    # EventBridge delivers events; Security Hub findings are in detail.findings
    logger.info("Received event with keys: %s", list(event.keys()))
    detail = event.get("detail", {})
    findings: List[Dict[str, Any]] = detail.get("findings", [])

    if not findings:
        logger.info("No findings in event; nothing to send")
        return {"status": "noop"}

    cfg = load_splunk_from_env()
    client = HECClient(cfg)

    mapped = [map_aws_security_hub_finding(f) for f in findings]
    client.send_events(mapped)
    logger.info("Forwarded %d findings to Splunk", len(mapped))
    return {"status": "ok", "forwarded": len(mapped)}
