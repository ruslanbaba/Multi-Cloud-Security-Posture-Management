from __future__ import annotations

from typing import Any, Dict
import datetime as dt


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def map_aws_security_hub_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    # Minimal, extensible mapping to CIM-like fields
    res = f.get("Resources", [{}])[0]
    account_id = f.get("AwsAccountId")
    region = f.get("Region") or res.get("Region")
    severity = (f.get("Severity") or {}).get("Label") or (f.get("Severity") or {}).get("Normalized")
    mapped = {
        "provider": "aws",
        "product": "security_hub",
        "ts_ingested": _now_iso(),
        "finding_id": f.get("Id"),
        "title": f.get("Title"),
        "description": f.get("Description"),
        "severity": severity,
        "account_id": account_id,
        "region": region,
        "resource_id": res.get("Id"),
        "resource_type": res.get("Type"),
        "types": f.get("Types"),
        "record_state": f.get("RecordState"),
        "compliance": (f.get("Compliance") or {}).get("Status"),
        "raw": f,
    }
    return mapped


def map_gcp_scc_finding(msg: Dict[str, Any]) -> Dict[str, Any]:
    # Supports Pub/Sub push message payload from SCC Notification
    finding = msg.get("finding") or {}
    source_properties = finding.get("sourceProperties", {})
    severity = finding.get("severity") or source_properties.get("Severity")
    mapped = {
        "provider": "gcp",
        "product": "scc",
        "ts_ingested": _now_iso(),
        "finding_id": finding.get("name"),
        "title": finding.get("category"),
        "description": finding.get("description"),
        "severity": severity,
        "project": finding.get("parent"),
        "resource_name": finding.get("resourceName"),
        "state": finding.get("state"),
        "raw": msg,
    }
    return mapped
