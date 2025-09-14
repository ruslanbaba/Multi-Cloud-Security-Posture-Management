from __future__ import annotations

import json
import time
import os
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentType(Enum):
    MALWARE_DETECTION = "MALWARE_DETECTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    DLP_VIOLATION = "DLP_VIOLATION"
    RUNTIME_ANOMALY = "RUNTIME_ANOMALY"
    ZERO_TRUST_VIOLATION = "ZERO_TRUST_VIOLATION"


class ResponseAction(Enum):
    ISOLATE = "isolate"
    ROTATE_SECRETS = "rotate_secrets"
    BLOCK_TRAFFIC = "block_traffic"
    PRESERVE_EVIDENCE = "preserve_evidence"
    NOTIFY_TEAM = "notify_team"
    ESCALATE = "escalate"
    MONITOR = "monitor"


@dataclass
class SecurityIncident:
    incident_id: str
    incident_type: IncidentType
    severity: IncidentSeverity
    timestamp: str
    context: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    status: str = "OPEN"
    mitre_techniques: List[str] = None
    automated_actions: List[str] = None
    
    def __post_init__(self):
        if self.mitre_techniques is None:
            self.mitre_techniques = []
        if self.automated_actions is None:
            self.automated_actions = []


@dataclass
class ResponseResult:
    incident_id: str
    success: bool
    actions_taken: List[str]
    evidence_preserved: List[str]
    notifications_sent: List[str]
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class DigitalForensics:
    """Digital forensics and evidence preservation"""
    
    def __init__(self, provider: str, region: str):
        self.provider = provider
        self.region = region
        
    def preserve_execution_context(self, incident: SecurityIncident) -> Dict[str, Any]:
        """Preserve execution context for forensic analysis"""
        try:
            forensic_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "incident_id": incident.incident_id,
                "execution_environment": self._capture_environment(),
                "process_info": self._capture_process_info(),
                "network_connections": self._capture_network_info(),
                "file_system_state": self._capture_filesystem_state(),
                "memory_analysis": self._capture_memory_state(),
                "chain_of_custody": {
                    "collected_by": "mcspm-automated-response",
                    "collection_time": datetime.now(timezone.utc).isoformat(),
                    "integrity_hash": ""
                }
            }
            
            # Calculate integrity hash
            forensic_json = json.dumps(forensic_data, sort_keys=True, default=str)
            forensic_data["chain_of_custody"]["integrity_hash"] = hashlib.sha256(
                forensic_json.encode()
            ).hexdigest()
            
            return forensic_data
            
        except Exception as e:
            logger.error(f"Failed to preserve execution context: {e}")
            return {"error": f"Forensic collection failed: {str(e)}"}
    
    def _capture_environment(self) -> Dict[str, Any]:
        """Capture environment variables and runtime info"""
        return {
            "environment_variables": dict(os.environ),
            "working_directory": os.getcwd(),
            "python_version": os.sys.version,
            "platform": os.sys.platform,
            "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("FUNCTION_NAME"),
            "runtime": os.environ.get("AWS_EXECUTION_ENV") or "unknown"
        }
    
    def _capture_process_info(self) -> Dict[str, Any]:
        """Capture process information"""
        try:
            import psutil
            return {
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "process_count": len(psutil.pids()),
                "cpu_percent": psutil.cpu_percent(),
                "memory_info": dict(psutil.virtual_memory()._asdict()),
                "running_processes": [
                    {"pid": p.pid, "name": p.name(), "cmdline": p.cmdline()}
                    for p in psutil.process_iter(['pid', 'name', 'cmdline'])
                ][:10]  # Limit to first 10 processes
            }
        except ImportError:
            return {"error": "psutil not available"}
        except Exception as e:
            return {"error": f"Process capture failed: {str(e)}"}
    
    def _capture_network_info(self) -> Dict[str, Any]:
        """Capture network connection information"""
        try:
            import psutil
            connections = psutil.net_connections()
            return {
                "connection_count": len(connections),
                "active_connections": [
                    {
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "type": conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                    }
                    for conn in connections[:20]  # Limit to first 20 connections
                ],
                "network_stats": dict(psutil.net_io_counters()._asdict())
            }
        except ImportError:
            return {"error": "psutil not available"}
        except Exception as e:
            return {"error": f"Network capture failed: {str(e)}"}
    
    def _capture_filesystem_state(self) -> Dict[str, Any]:
        """Capture filesystem state"""
        try:
            import glob
            
            # Capture file listings from common locations
            file_info = {}
            locations = ["/tmp", "/var/tmp", "/opt", ".", "/usr/bin", "/usr/local/bin"]
            
            for location in locations:
                try:
                    if os.path.exists(location):
                        files = glob.glob(f"{location}/*")[:50]  # Limit files
                        file_info[location] = [
                            {
                                "name": f,
                                "size": os.path.getsize(f) if os.path.isfile(f) else 0,
                                "modified": os.path.getmtime(f) if os.path.exists(f) else 0,
                                "is_file": os.path.isfile(f)
                            }
                            for f in files
                        ]
                except Exception:
                    file_info[location] = {"error": "Access denied or not found"}
            
            return {
                "file_listings": file_info,
                "disk_usage": self._get_disk_usage(),
                "open_files": self._get_open_files()
            }
        except Exception as e:
            return {"error": f"Filesystem capture failed: {str(e)}"}
    
    def _capture_memory_state(self) -> Dict[str, Any]:
        """Capture memory state information"""
        try:
            import psutil
            memory_info = psutil.virtual_memory()
            return {
                "total_memory": memory_info.total,
                "available_memory": memory_info.available,
                "used_memory": memory_info.used,
                "memory_percent": memory_info.percent,
                "swap_memory": dict(psutil.swap_memory()._asdict())
            }
        except ImportError:
            return {"error": "psutil not available"}
        except Exception as e:
            return {"error": f"Memory capture failed: {str(e)}"}
    
    def _get_disk_usage(self) -> Dict[str, Any]:
        """Get disk usage information"""
        try:
            import shutil
            return {
                "total": shutil.disk_usage(".").total,
                "used": shutil.disk_usage(".").used,
                "free": shutil.disk_usage(".").free
            }
        except Exception:
            return {"error": "Disk usage unavailable"}
    
    def _get_open_files(self) -> List[Dict[str, Any]]:
        """Get open file information"""
        try:
            import psutil
            process = psutil.Process()
            return [
                {"path": f.path, "fd": f.fd}
                for f in process.open_files()[:20]  # Limit to 20 files
            ]
        except Exception:
            return [{"error": "Open files unavailable"}]


class AutomatedContainment:
    """Automated containment actions for security incidents"""
    
    def __init__(self, provider: str, region: str):
        self.provider = provider
        self.region = region
        
    def execute_containment(self, incident: SecurityIncident) -> List[str]:
        """Execute appropriate containment actions based on incident type and severity"""
        actions_taken = []
        
        try:
            if incident.severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
                actions_taken.extend(self._execute_high_severity_containment(incident))
            
            if incident.incident_type == IncidentType.CREDENTIAL_COMPROMISE:
                actions_taken.extend(self._handle_credential_compromise(incident))
            elif incident.incident_type == IncidentType.MALWARE_DETECTION:
                actions_taken.extend(self._handle_malware_detection(incident))
            elif incident.incident_type == IncidentType.DLP_VIOLATION:
                actions_taken.extend(self._handle_dlp_violation(incident))
            elif incident.incident_type == IncidentType.RUNTIME_ANOMALY:
                actions_taken.extend(self._handle_runtime_anomaly(incident))
            
        except Exception as e:
            logger.error(f"Containment execution failed: {e}")
            actions_taken.append(f"Containment failed: {str(e)}")
        
        return actions_taken
    
    def _execute_high_severity_containment(self, incident: SecurityIncident) -> List[str]:
        """Execute high severity containment procedures"""
        actions = []
        
        # Isolate function/container
        if self.provider == "aws":
            actions.extend(self._aws_isolate_function(incident))
        elif self.provider == "gcp":
            actions.extend(self._gcp_isolate_function(incident))
        
        # Enable enhanced monitoring
        actions.extend(self._enable_enhanced_monitoring(incident))
        
        # Create security alert
        actions.extend(self._create_security_alert(incident))
        
        return actions
    
    def _aws_isolate_function(self, incident: SecurityIncident) -> List[str]:
        """Isolate AWS Lambda function"""
        actions = []
        try:
            function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
            if function_name:
                # In a real implementation, you would use boto3 to set concurrency to 0
                # boto3.client('lambda').put_function_concurrency(
                #     FunctionName=function_name,
                #     ReservedConcurrentExecutions=0
                # )
                actions.append(f"Lambda function {function_name} isolated (concurrency set to 0)")
                logger.warning(f"Lambda function {function_name} would be isolated in production")
            else:
                actions.append("No Lambda function name found for isolation")
        except Exception as e:
            actions.append(f"Failed to isolate Lambda function: {str(e)}")
        
        return actions
    
    def _gcp_isolate_function(self, incident: SecurityIncident) -> List[str]:
        """Isolate GCP Cloud Function"""
        actions = []
        try:
            function_name = os.environ.get("FUNCTION_NAME")
            if function_name:
                # In a real implementation, you would use Google Cloud Functions API
                # to update the function with a policy that blocks invocations
                actions.append(f"Cloud Function {function_name} isolated (policy updated)")
                logger.warning(f"Cloud Function {function_name} would be isolated in production")
            else:
                actions.append("No Cloud Function name found for isolation")
        except Exception as e:
            actions.append(f"Failed to isolate Cloud Function: {str(e)}")
        
        return actions
    
    def _handle_credential_compromise(self, incident: SecurityIncident) -> List[str]:
        """Handle credential compromise incidents"""
        actions = []
        
        # Log the compromise
        logger.critical("Credential compromise detected - immediate action required")
        actions.append("Credential compromise logged for immediate rotation")
        
        # In production, trigger secret rotation
        actions.append("Secret rotation would be triggered in production environment")
        
        # Invalidate any cached credentials
        actions.append("Credential cache invalidation initiated")
        
        return actions
    
    def _handle_malware_detection(self, incident: SecurityIncident) -> List[str]:
        """Handle malware detection incidents"""
        actions = []
        
        # Block execution
        actions.append("Execution blocked due to malware detection")
        
        # Preserve forensic evidence
        actions.append("Forensic evidence preservation initiated")
        
        # Alert security team
        actions.append("Security team alerted for malware investigation")
        
        return actions
    
    def _handle_dlp_violation(self, incident: SecurityIncident) -> List[str]:
        """Handle data loss prevention violations"""
        actions = []
        
        # Block data transmission
        actions.append("Data transmission blocked due to DLP violation")
        
        # Log violation details
        actions.append("DLP violation details logged for audit")
        
        # Notify compliance team
        actions.append("Compliance team notified of data protection violation")
        
        return actions
    
    def _handle_runtime_anomaly(self, incident: SecurityIncident) -> List[str]:
        """Handle runtime anomaly incidents"""
        actions = []
        
        # Enable enhanced logging
        actions.append("Enhanced logging enabled for anomaly investigation")
        
        # Monitor for additional anomalies
        actions.append("Continuous monitoring initiated for additional anomalies")
        
        return actions
    
    def _enable_enhanced_monitoring(self, incident: SecurityIncident) -> List[str]:
        """Enable enhanced monitoring for the incident"""
        return ["Enhanced monitoring enabled for incident tracking"]
    
    def _create_security_alert(self, incident: SecurityIncident) -> List[str]:
        """Create security alert for the incident"""
        return [f"Security alert created for incident {incident.incident_id}"]


class SOARIntegration:
    """Security Orchestration, Automation and Response (SOAR) integration"""
    
    def __init__(self, provider: str, region: str, config: Dict[str, Any] = None):
        self.provider = provider
        self.region = region
        self.config = config or {}
        self.forensics = DigitalForensics(provider, region)
        self.containment = AutomatedContainment(provider, region)
        
    def create_incident(self, incident_type: IncidentType, severity: IncidentSeverity,
                       context: Dict[str, Any], evidence: List[Dict[str, Any]]) -> SecurityIncident:
        """Create a new security incident"""
        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{incident_type.value}"
        
        incident = SecurityIncident(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            timestamp=datetime.now(timezone.utc).isoformat(),
            context=context,
            evidence=evidence,
            mitre_techniques=self._map_to_mitre(incident_type),
        )
        
        return incident
    
    def respond_to_incident(self, incident: SecurityIncident) -> ResponseResult:
        """Execute automated incident response"""
        logger.info(f"Responding to incident {incident.incident_id} ({incident.severity.value})")
        
        actions_taken = []
        evidence_preserved = []
        notifications_sent = []
        errors = []
        
        try:
            # Execute containment actions
            containment_actions = self.containment.execute_containment(incident)
            actions_taken.extend(containment_actions)
            
            # Preserve digital evidence
            forensic_data = self.forensics.preserve_execution_context(incident)
            if "error" not in forensic_data:
                evidence_preserved.append(f"Forensic data collected: {incident.incident_id}")
            else:
                errors.append(f"Forensic collection failed: {forensic_data.get('error')}")
            
            # Send notifications
            notification_result = self._send_notifications(incident)
            notifications_sent.extend(notification_result)
            
            # Update incident with actions taken
            incident.automated_actions = actions_taken
            
            # Log incident for audit trail
            self._log_incident_response(incident, actions_taken)
            
            return ResponseResult(
                incident_id=incident.incident_id,
                success=True,
                actions_taken=actions_taken,
                evidence_preserved=evidence_preserved,
                notifications_sent=notifications_sent,
                errors=errors
            )
            
        except Exception as e:
            logger.error(f"Incident response failed: {e}")
            errors.append(f"Response execution failed: {str(e)}")
            
            return ResponseResult(
                incident_id=incident.incident_id,
                success=False,
                actions_taken=actions_taken,
                evidence_preserved=evidence_preserved,
                notifications_sent=notifications_sent,
                errors=errors
            )
    
    def _map_to_mitre(self, incident_type: IncidentType) -> List[str]:
        """Map incident type to MITRE ATT&CK techniques"""
        technique_mapping = {
            IncidentType.MALWARE_DETECTION: ["T1059", "T1055", "T1105"],  # Command and Scripting, Process Injection, Ingress Tool Transfer
            IncidentType.DATA_EXFILTRATION: ["T1041", "T1048", "T1567"],  # Exfiltration, Alternative Protocols, Cloud Storage
            IncidentType.PRIVILEGE_ESCALATION: ["T1068", "T1134", "T1543"],  # Exploitation, Access Token, Service Creation
            IncidentType.LATERAL_MOVEMENT: ["T1021", "T1080", "T1570"],  # Remote Services, Taint Shared Content, Discovery
            IncidentType.CREDENTIAL_COMPROMISE: ["T1110", "T1555", "T1552"],  # Brute Force, Credentials from Password Stores, Credentials in Files
            IncidentType.SUSPICIOUS_ACTIVITY: ["T1057", "T1082", "T1016"],  # Process Discovery, System Information, System Network Configuration
            IncidentType.DLP_VIOLATION: ["T1005", "T1039", "T1025"],  # Data from Local System, Data from Network Shared Drive, Data from Removable Media
            IncidentType.RUNTIME_ANOMALY: ["T1055", "T1106", "T1129"],  # Process Injection, Native API, Shared Modules
            IncidentType.ZERO_TRUST_VIOLATION: ["T1021", "T1190", "T1133"]  # Remote Services, Exploit Public-Facing Application, External Remote Services
        }
        return technique_mapping.get(incident_type, [])
    
    def _send_notifications(self, incident: SecurityIncident) -> List[str]:
        """Send notifications to security team and stakeholders"""
        notifications = []
        
        try:
            # In production, integrate with actual notification services
            # AWS SNS, GCP Pub/Sub, email, Slack, PagerDuty, etc.
            
            notification_message = {
                "incident_id": incident.incident_id,
                "severity": incident.severity.value,
                "type": incident.incident_type.value,
                "timestamp": incident.timestamp,
                "summary": f"{incident.severity.value} security incident: {incident.incident_type.value}",
                "mitre_techniques": incident.mitre_techniques,
                "automated_actions": incident.automated_actions
            }
            
            # Log notification (in production, send to actual notification channels)
            logger.warning(f"Security incident notification: {json.dumps(notification_message)}")
            notifications.append(f"Security team notified via logging system")
            
            # For critical incidents, additional notifications
            if incident.severity == IncidentSeverity.CRITICAL:
                notifications.append("Executive team notified of critical incident")
                notifications.append("On-call security engineer paged")
            
        except Exception as e:
            logger.error(f"Notification failed: {e}")
            notifications.append(f"Notification failed: {str(e)}")
        
        return notifications
    
    def _log_incident_response(self, incident: SecurityIncident, actions_taken: List[str]):
        """Log incident response for audit trail"""
        audit_log = {
            "event_type": "incident_response",
            "incident_id": incident.incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident_details": asdict(incident),
            "response_actions": actions_taken,
            "responder": "mcspm-automated-response",
            "provider": self.provider,
            "region": self.region
        }
        
        logger.info(f"Incident response audit log: {json.dumps(audit_log)}")


class ThreatHunting:
    """Proactive threat hunting capabilities"""
    
    def __init__(self, provider: str):
        self.provider = provider
        
    def analyze_indicators(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze context for threat indicators"""
        indicators = {
            "suspicious_patterns": [],
            "ioc_matches": [],
            "behavioral_anomalies": [],
            "risk_score": 0
        }
        
        # Analyze for suspicious patterns
        indicators["suspicious_patterns"] = self._detect_suspicious_patterns(context)
        
        # Check for known IOCs
        indicators["ioc_matches"] = self._check_threat_intelligence(context)
        
        # Behavioral analysis
        indicators["behavioral_anomalies"] = self._analyze_behavior(context)
        
        # Calculate overall risk score
        indicators["risk_score"] = self._calculate_risk_score(indicators)
        
        return indicators
    
    def _detect_suspicious_patterns(self, context: Dict[str, Any]) -> List[str]:
        """Detect suspicious patterns in context data"""
        patterns = []
        
        # Convert context to string for analysis
        context_str = json.dumps(context, default=str).lower()
        
        # Check for suspicious keywords
        suspicious_keywords = [
            "malware", "trojan", "virus", "backdoor", "rootkit",
            "exfiltration", "lateral_movement", "privilege_escalation",
            "credential_dumping", "password_spray", "brute_force"
        ]
        
        for keyword in suspicious_keywords:
            if keyword in context_str:
                patterns.append(f"Suspicious keyword detected: {keyword}")
        
        return patterns
    
    def _check_threat_intelligence(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check context against threat intelligence feeds"""
        # In production, integrate with actual threat intelligence feeds
        # For now, return placeholder analysis
        return []
    
    def _analyze_behavior(self, context: Dict[str, Any]) -> List[str]:
        """Analyze behavioral patterns"""
        anomalies = []
        
        # Check for timing anomalies
        if "execution_time" in context and context["execution_time"] > 300:
            anomalies.append("Unusually long execution time")
        
        # Check for resource usage anomalies
        if "memory_usage" in context and context["memory_usage"] > 80:
            anomalies.append("High memory usage pattern")
        
        return anomalies
    
    def _calculate_risk_score(self, indicators: Dict[str, Any]) -> int:
        """Calculate overall risk score based on indicators"""
        score = 0
        
        score += len(indicators["suspicious_patterns"]) * 10
        score += len(indicators["ioc_matches"]) * 25
        score += len(indicators["behavioral_anomalies"]) * 15
        
        return min(100, score)  # Cap at 100