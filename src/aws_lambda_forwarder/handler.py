from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

from common.config import load_splunk_from_env, SplunkConfig
from common.hec import HECClient
from common.mappings import map_aws_security_hub_finding
from common.runtime_security import RuntimeSecurityMonitor
from common.data_protection import EnhancedDLPScanner, EnvelopeEncryption, FieldLevelEncryption
from common.incident_response import SOARIntegration, IncidentType, IncidentSeverity, ThreatHunting


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize security monitoring and data protection
security_monitor = RuntimeSecurityMonitor({
    "provider": "aws",
    "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unknown")
})
security_logger = SecurityEventLogger()
dlp_scanner = EnhancedDLPScanner({
    "enable_ml_detection": os.environ.get("ENABLE_ML_DLP", "false").lower() == "true"
})

# Initialize encryption if KMS key is available
kms_key_arn = os.environ.get("AWS_KMS_KEY_ARN")
if kms_key_arn:
    envelope_encryption = EnvelopeEncryption("aws", os.environ.get("AWS_REGION"), kms_key_arn)
else:
    envelope_encryption = None

# Initialize incident response and threat hunting
soar_integration = SOARIntegration("aws", os.environ.get("AWS_REGION", "us-east-1"))
threat_hunting = ThreatHunting("aws")


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
    # Perform runtime security assessment
    threat_assessment = security_monitor.check_runtime_anomalies()
    
    # Log security assessment
    security_context = {
        "account_id": os.environ.get("AWS_ACCOUNT_ID"),
        "region": os.environ.get("AWS_REGION"),
        "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    }
    security_logger.log_threat_assessment(threat_assessment, security_context)
    
    # Handle critical/high threats
    if threat_assessment.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
        logger.error(f"High threat detected: {threat_assessment.threat_level.value}, Risk Score: {threat_assessment.risk_score}")
        # In production, you might want to exit early or take containment actions
        if threat_assessment.threat_level == ThreatLevel.CRITICAL:
            return {
                "status": "blocked",
                "reason": "Critical security threat detected",
                "threat_level": threat_assessment.threat_level.value,
                "risk_score": threat_assessment.risk_score
            }
    
    # EventBridge delivers events; Security Hub findings are in detail.findings
    logger.info("Received event with keys: %s", list(event.keys()))
    detail = event.get("detail", {})
    findings: List[Dict[str, Any]] = detail.get("findings", [])

    if not findings:
        logger.info("No findings in event; nothing to send")
        return {"status": "noop"}

    cfg = _load_cfg_with_optional_secret()
    client = HECClient(cfg)

    # Enhance findings with security context and data protection
    mapped = []
    for f in findings:
        mapped_finding = map_aws_security_hub_finding(f)
        
        # Apply data protection scanning
        try:
            has_violations, violations = dlp_scanner.scan_payload(mapped_finding)
            if has_violations:
                logger.warning(f"DLP violations detected: {len(violations)} violations")
                # Apply sanitization based on violation actions
                mapped_finding = dlp_scanner.sanitize_payload(mapped_finding, violations)
                # Add DLP metadata
                mapped_finding["dlp_analysis"] = {
                    "violations_count": len(violations),
                    "highest_severity": max(v.severity.value for v in violations) if violations else "NONE",
                    "actions_taken": [v.action.value for v in violations]
                }
        except Exception as e:
            logger.error(f"DLP scanning failed: {e}")
            mapped_finding["dlp_analysis"] = {"error": "DLP scanning failed"}
        
        # Apply envelope encryption for large payloads if enabled
        if envelope_encryption:
            try:
                mapped_finding = envelope_encryption.encrypt_large_payload(mapped_finding)
            except Exception as e:
                logger.error(f"Envelope encryption failed: {e}")
        
        # Add runtime security metadata
        mapped_finding["runtime_security"] = {
            "threat_level": threat_assessment.threat_level.value,
            "risk_score": threat_assessment.risk_score,
            "anomaly_count": len(threat_assessment.anomalies),
            "ioc_matches": len(threat_assessment.ioc_matches)
        }
        
        # Perform threat hunting analysis
        try:
            threat_indicators = threat_hunting.analyze_indicators(mapped_finding)
            mapped_finding["threat_hunting"] = threat_indicators
            
            # Trigger automated incident response for high-risk findings
            if threat_indicators["risk_score"] >= 70 or threat_assessment.threat_level.value in ["HIGH", "CRITICAL"]:
                incident_type = _determine_incident_type(mapped_finding, violations if 'violations' in locals() else [])
                incident_severity = _determine_incident_severity(threat_assessment.threat_level.value, threat_indicators["risk_score"])
                
                # Create and respond to incident
                incident = soar_integration.create_incident(
                    incident_type=incident_type,
                    severity=incident_severity,
                    context=mapped_finding,
                    evidence=[f]  # Original finding as evidence
                )
                
                response_result = soar_integration.respond_to_incident(incident)
                
                # Add incident response metadata to finding
                mapped_finding["incident_response"] = {
                    "incident_id": incident.incident_id,
                    "severity": incident.severity.value,
                    "actions_taken": response_result.actions_taken,
                    "success": response_result.success
                }
                
                logger.info(f"Automated incident response triggered: {incident.incident_id}")
                
        except Exception as e:
            logger.error(f"Threat hunting and incident response failed: {e}")
            mapped_finding["threat_hunting"] = {"error": "Analysis failed"}
        
        mapped.append(mapped_finding)
    
    client.send_events(mapped)
    logger.info("Forwarded %d findings to Splunk with security context", len(mapped))
    return {
        "status": "ok", 
        "forwarded": len(mapped),
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
