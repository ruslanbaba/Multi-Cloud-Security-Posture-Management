from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any, Dict

from common.config import load_splunk_from_env
from common.hec import HECClient
from common.mappings import map_gcp_scc_finding
from common.runtime_security import RuntimeSecurityMonitor, SecurityEventLogger, ThreatLevel
from common.data_protection import EnhancedDLPScanner, EnvelopeEncryption, FieldLevelEncryption
from common.incident_response import SOARIntegration, IncidentType, IncidentSeverity, ThreatHunting


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize security monitoring and data protection
security_monitor = RuntimeSecurityMonitor({
    "provider": "gcp",
    "function_name": os.environ.get("FUNCTION_NAME", "unknown")
})
security_logger = SecurityEventLogger()
dlp_scanner = EnhancedDLPScanner({
    "enable_ml_detection": os.environ.get("ENABLE_ML_DLP", "false").lower() == "true"
})

# Initialize encryption if KMS key is available
kms_key_name = os.environ.get("GCP_KMS_KEY_NAME")
if kms_key_name:
    envelope_encryption = EnvelopeEncryption("gcp", os.environ.get("GCP_REGION"), kms_key_name)
else:
    envelope_encryption = None

# Initialize incident response and threat hunting
soar_integration = SOARIntegration("gcp", os.environ.get("GCP_REGION", "us-central1"))
threat_hunting = ThreatHunting("gcp")


def pubsub_entrypoint(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    # Perform runtime security assessment
    threat_assessment = security_monitor.check_runtime_anomalies()
    
    # Log security assessment
    security_context = {
        "project_id": os.environ.get("GCP_PROJECT_ID"),
        "region": os.environ.get("GCP_REGION"),
        "function_name": os.environ.get("FUNCTION_NAME")
    }
    security_logger.log_threat_assessment(threat_assessment, security_context)
    
    # Handle critical/high threats
    if threat_assessment.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
        logger.error(f"High threat detected: {threat_assessment.threat_level.value}, Risk Score: {threat_assessment.risk_score}")
        if threat_assessment.threat_level == ThreatLevel.CRITICAL:
            return {
                "status": "blocked",
                "reason": "Critical security threat detected",
                "threat_level": threat_assessment.threat_level.value,
                "risk_score": threat_assessment.risk_score
            }
    
    # Pub/Sub message with base64-encoded data
    data_b64 = event.get("data")
    if not data_b64:
        logger.info("No data in Pub/Sub event; noop")
        return {"status": "noop"}
    decoded = base64.b64decode(data_b64).decode("utf-8")
    msg = json.loads(decoded)

    cfg = load_splunk_from_env()
    client = HECClient(cfg)

    # Enhance finding with security context and data protection
    mapped = map_gcp_scc_finding(msg)
    
    # Apply data protection scanning
    try:
        has_violations, violations = dlp_scanner.scan_payload(mapped)
        if has_violations:
            logger.warning(f"DLP violations detected: {len(violations)} violations")
            # Apply sanitization based on violation actions
            mapped = dlp_scanner.sanitize_payload(mapped, violations)
            # Add DLP metadata
            mapped["dlp_analysis"] = {
                "violations_count": len(violations),
                "highest_severity": max(v.severity.value for v in violations) if violations else "NONE",
                "actions_taken": [v.action.value for v in violations]
            }
    except Exception as e:
        logger.error(f"DLP scanning failed: {e}")
        mapped["dlp_analysis"] = {"error": "DLP scanning failed"}
    
    # Apply envelope encryption for large payloads if enabled
    if envelope_encryption:
        try:
            mapped = envelope_encryption.encrypt_large_payload(mapped)
        except Exception as e:
            logger.error(f"Envelope encryption failed: {e}")
    
    # Add runtime security metadata
    mapped["runtime_security"] = {
        "threat_level": threat_assessment.threat_level.value,
        "risk_score": threat_assessment.risk_score,
        "anomaly_count": len(threat_assessment.anomalies),
        "ioc_matches": len(threat_assessment.ioc_matches)
    }
    
    # Perform threat hunting analysis
    try:
        threat_indicators = threat_hunting.analyze_indicators(mapped)
        mapped["threat_hunting"] = threat_indicators
        
        # Trigger automated incident response for high-risk findings
        if threat_indicators["risk_score"] >= 70 or threat_assessment.threat_level.value in ["HIGH", "CRITICAL"]:
            incident_type = _determine_incident_type(mapped, violations if 'violations' in locals() else [])
            incident_severity = _determine_incident_severity(threat_assessment.threat_level.value, threat_indicators["risk_score"])
            
            # Create and respond to incident
            incident = soar_integration.create_incident(
                incident_type=incident_type,
                severity=incident_severity,
                context=mapped,
                evidence=[msg]  # Original SCC finding as evidence
            )
            
            response_result = soar_integration.respond_to_incident(incident)
            
            # Add incident response metadata to finding
            mapped["incident_response"] = {
                "incident_id": incident.incident_id,
                "severity": incident.severity.value,
                "actions_taken": response_result.actions_taken,
                "success": response_result.success
            }
            
            logger.info(f"Automated incident response triggered: {incident.incident_id}")
            
    except Exception as e:
        logger.error(f"Threat hunting and incident response failed: {e}")
        mapped["threat_hunting"] = {"error": "Analysis failed"}
    
    client.send_events([mapped])
    logger.info("Forwarded 1 SCC finding to Splunk with security context")
    return {
        "status": "ok", 
        "forwarded": 1,
        "security_assessment": {
            "threat_level": threat_assessment.threat_level.value,
            "risk_score": threat_assessment.risk_score
        }
    }


def _determine_incident_type(finding: Dict[str, Any], dlp_violations: List) -> IncidentType:
    """Determine incident type based on finding content and violations"""
    
    # Check for DLP violations first
    if dlp_violations:
        return IncidentType.DLP_VIOLATION
    
    # Analyze finding content
    finding_str = json.dumps(finding, default=str).lower()
    
    if any(term in finding_str for term in ["malware", "virus", "trojan", "backdoor"]):
        return IncidentType.MALWARE_DETECTION
    elif any(term in finding_str for term in ["credential", "password", "key", "token"]):
        return IncidentType.CREDENTIAL_COMPROMISE
    elif any(term in finding_str for term in ["privilege", "escalation", "elevation"]):
        return IncidentType.PRIVILEGE_ESCALATION
    elif any(term in finding_str for term in ["lateral", "movement", "pivot"]):
        return IncidentType.LATERAL_MOVEMENT
    elif any(term in finding_str for term in ["exfiltration", "data_theft", "unauthorized_access"]):
        return IncidentType.DATA_EXFILTRATION
    elif "runtime_security" in finding and finding["runtime_security"].get("anomaly_count", 0) > 0:
        return IncidentType.RUNTIME_ANOMALY
    else:
        return IncidentType.SUSPICIOUS_ACTIVITY


def _determine_incident_severity(threat_level: str, risk_score: int) -> IncidentSeverity:
    """Determine incident severity based on threat level and risk score"""
    
    if threat_level == "CRITICAL" or risk_score >= 90:
        return IncidentSeverity.CRITICAL
    elif threat_level == "HIGH" or risk_score >= 70:
        return IncidentSeverity.HIGH
    elif threat_level == "MEDIUM" or risk_score >= 50:
        return IncidentSeverity.MEDIUM
    else:
        return IncidentSeverity.LOW
