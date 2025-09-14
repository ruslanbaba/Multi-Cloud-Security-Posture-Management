from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict

from common.config import load_splunk_from_env
from common.hec import HECClient
from common.mappings import map_gcp_scc_finding


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def pubsub_entrypoint(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    # Pub/Sub message with base64-encoded data
    data_b64 = event.get("data")
    if not data_b64:
        logger.info("No data in Pub/Sub event; noop")
        return {"status": "noop"}
    decoded = base64.b64decode(data_b64).decode("utf-8")
    msg = json.loads(decoded)

    cfg = load_splunk_from_env()
    client = HECClient(cfg)

    mapped = map_gcp_scc_finding(msg)
    client.send_events([mapped])
    logger.info("Forwarded 1 SCC finding to Splunk")
    return {"status": "ok", "forwarded": 1}
