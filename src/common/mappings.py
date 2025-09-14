from __future__ import annotations

from typing import Any, Dict
import datetime as dt


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def map_aws_security_hub_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    # Enhanced CIM-like mapping with metadata enrichment
    res = f.get("Resources", [{}])[0]
    account_id = f.get("AwsAccountId")
    region = f.get("Region") or res.get("Region")
    severity = (f.get("Severity") or {}).get("Label") or (f.get("Severity") or {}).get("Normalized")
    
    # Extract tags from resource if available
    tags = res.get("Tags", {})
    resource_details = res.get("Details", {})
    
    # Normalize severity to numeric for analytics
    severity_score = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(str(severity).upper(), 0)
    
    mapped = {
        "provider": "aws",
        "product": "security_hub",
        "ts_ingested": _now_iso(),
        "finding_id": f.get("Id"),
        "title": f.get("Title"),
        "description": f.get("Description"),
        "severity": severity,
        "severity_score": severity_score,
        "account_id": account_id,
        "region": region,
        "resource_id": res.get("Id"),
        "resource_type": res.get("Type"),
        "resource_tags": tags,
        "resource_details": resource_details,
        "types": f.get("Types"),
        "record_state": f.get("RecordState"),
        "workflow_state": f.get("WorkflowState"),
        "compliance": (f.get("Compliance") or {}).get("Status"),
        "confidence": f.get("Confidence"),
        "criticality": f.get("Criticality"),
        "generator_id": f.get("GeneratorId"),
        "product_arn": f.get("ProductArn"),
        "company_name": f.get("CompanyName"),
        "created_at": f.get("CreatedAt"),
        "updated_at": f.get("UpdatedAt"),
        "remediation": f.get("Remediation"),
        "source_url": f.get("SourceUrl"),
        "network": f.get("Network"),
        "process": f.get("Process"),
        "threats": f.get("ThreatIntelIndicators"),
        "malware": f.get("Malware"),
        "raw": f,
    }
    return mapped


def map_gcp_scc_finding(msg: Dict[str, Any]) -> Dict[str, Any]:
    # Enhanced SCC mapping with project metadata and enrichment
    finding = msg.get("finding") or {}
    source_properties = finding.get("sourceProperties", {})
    severity = finding.get("severity") or source_properties.get("Severity")
    
    # Extract project info from resource name
    resource_name = finding.get("resourceName", "")
    project_id = ""
    if "projects/" in resource_name:
        try:
            project_id = resource_name.split("projects/")[1].split("/")[0]
        except (IndexError, AttributeError):
            pass
    
    # Normalize severity to numeric
    severity_score = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(str(severity).upper(), 0)
    
    # Extract additional metadata
    security_marks = finding.get("securityMarks", {})
    external_systems = finding.get("externalSystems", {})
    
    mapped = {
        "provider": "gcp",
        "product": "scc",
        "ts_ingested": _now_iso(),
        "finding_id": finding.get("name"),
        "title": finding.get("category"),
        "description": finding.get("description"),
        "severity": severity,
        "severity_score": severity_score,
        "project_id": project_id,
        "resource_name": resource_name,
        "resource_display_name": finding.get("resourceDisplayName"),
        "state": finding.get("state"),
        "category": finding.get("category"),
        "source_properties": source_properties,
        "security_marks": security_marks,
        "external_systems": external_systems,
        "event_time": finding.get("eventTime"),
        "create_time": finding.get("createTime"),
        "canonical_name": finding.get("canonicalName"),
        "mute": finding.get("mute"),
        "finding_class": finding.get("findingClass"),
        "indicator": finding.get("indicator"),
        "vulnerability": finding.get("vulnerability"),
        "mute_update_time": finding.get("muteUpdateTime"),
        "external_uri": finding.get("externalUri"),
        "raw": msg,
    }
    return mapped
