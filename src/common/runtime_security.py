from __future__ import annotations

import hashlib
import time
import os
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatAssessment:
    risk_score: float
    threat_level: ThreatLevel
    anomalies: List[str]
    ioc_matches: List[Dict[str, Any]]
    recommended_actions: List[str]
    execution_context: Dict[str, Any]


@dataclass
class RuntimeMetrics:
    startup_time: float
    memory_usage: float
    execution_duration: float
    network_connections: int
    file_access_count: int
    environment_vars: Dict[str, str]


class RuntimeSecurityMonitor:
    """Advanced runtime security monitoring with behavioral analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.baseline_metrics = self._establish_baseline()
        self.threat_indicators: List[str] = []
        self.ioc_patterns = self._load_threat_intelligence()
        self.execution_start = time.time()
    
    def _establish_baseline(self) -> Dict[str, Any]:
        """Establish runtime baseline metrics for anomaly detection"""
        try:
            import psutil
            memory_info = psutil.virtual_memory()
            process_count = len(psutil.pids())
        except ImportError:
            # Fallback for environments without psutil
            memory_info = None
            process_count = 0
        
        return {
            "startup_time": time.time(),
            "expected_memory_threshold": 512,  # MB
            "max_execution_time": 300,  # 5 minutes
            "expected_env_vars": set(os.environ.keys()),
            "file_integrity_hash": self._calculate_code_hash(),
            "memory_baseline": memory_info.percent if memory_info else 0,
            "process_baseline": process_count
        }
    
    def _calculate_code_hash(self) -> str:
        """Calculate hash of critical code files for integrity verification"""
        try:
            import glob
            code_files = []
            
            # Check common Lambda/Function paths
            for pattern in ["/var/task/**/*.py", "/workspace/**/*.py", "./**/*.py"]:
                try:
                    code_files.extend(glob.glob(pattern, recursive=True))
                except Exception:
                    continue
            
            if not code_files:
                return "no-files-found"
            
            combined_hash = hashlib.sha256()
            for file_path in sorted(code_files):
                try:
                    if os.path.isfile(file_path) and file_path.endswith('.py'):
                        with open(file_path, 'rb') as f:
                            combined_hash.update(f.read())
                except Exception:
                    continue
            
            return combined_hash.hexdigest()
        except Exception as e:
            logger.warning(f"Failed to calculate code hash: {e}")
            return "hash-calculation-failed"
    
    def _load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence patterns and IOCs"""
        return {
            "suspicious_commands": [
                "wget", "curl", "nc", "netcat", "bash", "/bin/sh",
                "powershell", "cmd.exe", "certutil", "bitsadmin"
            ],
            "suspicious_files": [
                "/tmp/", "/var/tmp/", "C:\\Windows\\Temp\\",
                ".exe", ".bat", ".cmd", ".ps1", ".vbs"
            ],
            "suspicious_networks": [
                "tor", "onion", "darkweb", "malware",
                "botnet", "c2", "command-and-control"
            ],
            "known_malware_hashes": set([
                # Example IOC hashes - in production, load from threat feeds
                "e3b0c44298fc1c149afbf4c8996fb924",
                "d41d8cd98f00b204e9800998ecf8427e"
            ])
        }
    
    def validate_execution_context(self) -> Dict[str, Any]:
        """Validate the execution environment hasn't been tampered with"""
        context = {
            "valid": True,
            "anomalies": [],
            "risk_score": 0,
            "environment": "unknown"
        }
        
        # Detect execution environment
        if "AWS_LAMBDA_FUNCTION_NAME" in os.environ:
            context["environment"] = "aws_lambda"
            expected_vars = [
                "AWS_LAMBDA_FUNCTION_NAME",
                "AWS_LAMBDA_FUNCTION_VERSION",
                "AWS_REGION",
                "AWS_EXECUTION_ENV"
            ]
        elif "FUNCTION_NAME" in os.environ:
            context["environment"] = "gcp_function"
            expected_vars = [
                "FUNCTION_NAME",
                "FUNCTION_TARGET",
                "GCP_PROJECT",
                "FUNCTION_REGION"
            ]
        else:
            context["environment"] = "unknown"
            expected_vars = []
        
        # Check for expected environment variables
        for var in expected_vars:
            if var not in os.environ:
                context["anomalies"].append(f"Missing expected environment variable: {var}")
                context["risk_score"] += 10
        
        # Check for suspicious environment modifications
        suspicious_vars = ["LD_PRELOAD", "PYTHONPATH", "PATH"]
        for var in suspicious_vars:
            if var in os.environ:
                value = os.environ[var]
                if any(suspicious in value.lower() for suspicious in ["tmp", "temp", "malware", "/dev/shm"]):
                    context["anomalies"].append(f"Suspicious environment variable value: {var}={value}")
                    context["risk_score"] += 25
        
        # Validate code integrity
        current_hash = self._calculate_code_hash()
        expected_hash = self.baseline_metrics.get("file_integrity_hash", "")
        if current_hash != expected_hash and expected_hash != "no-files-found":
            context["anomalies"].append("Code integrity violation detected")
            context["risk_score"] += 50
        
        # Check for unexpected new environment variables
        current_env = set(os.environ.keys())
        baseline_env = self.baseline_metrics["expected_env_vars"]
        new_vars = current_env - baseline_env
        if new_vars:
            # Filter out expected dynamic variables
            unexpected_vars = [var for var in new_vars if not any(
                prefix in var for prefix in ["AWS_", "LAMBDA_", "FUNCTION_", "TMP"]
            )]
            if unexpected_vars:
                context["anomalies"].append(f"Unexpected environment variables: {unexpected_vars}")
                context["risk_score"] += 15
        
        context["valid"] = context["risk_score"] < 30
        return context
    
    def check_runtime_anomalies(self) -> ThreatAssessment:
        """Perform comprehensive runtime security analysis"""
        anomalies = []
        ioc_matches = []
        current_time = time.time()
        
        # Execution context validation
        execution_context = self.validate_execution_context()
        anomalies.extend(execution_context["anomalies"])
        
        # Execution time anomaly detection
        execution_duration = current_time - self.execution_start
        max_execution = self.baseline_metrics["max_execution_time"]
        if execution_duration > max_execution:
            anomalies.append(f"Unusually long execution time: {execution_duration:.1f}s (max: {max_execution}s)")
        
        # Memory usage analysis (if available)
        try:
            import psutil
            current_memory = psutil.virtual_memory().percent
            memory_threshold = self.baseline_metrics.get("expected_memory_threshold", 80)
            if current_memory > memory_threshold:
                anomalies.append(f"High memory usage: {current_memory}% (threshold: {memory_threshold}%)")
        except ImportError:
            pass
        
        # Process analysis
        suspicious_processes = self._analyze_processes()
        if suspicious_processes:
            anomalies.extend(suspicious_processes)
        
        # Network activity analysis
        network_anomalies = self._analyze_network_activity()
        if network_anomalies:
            anomalies.extend(network_anomalies)
        
        # IOC analysis
        ioc_matches = self._check_iocs()
        
        # Calculate risk score
        base_risk = execution_context["risk_score"]
        anomaly_risk = len(anomalies) * 5
        ioc_risk = len(ioc_matches) * 20
        total_risk = base_risk + anomaly_risk + ioc_risk
        
        # Determine threat level
        if total_risk >= 80:
            threat_level = ThreatLevel.CRITICAL
        elif total_risk >= 50:
            threat_level = ThreatLevel.HIGH
        elif total_risk >= 25:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        # Generate recommended actions
        recommended_actions = self._get_recommended_actions(threat_level, anomalies, ioc_matches)
        
        return ThreatAssessment(
            risk_score=total_risk,
            threat_level=threat_level,
            anomalies=anomalies,
            ioc_matches=ioc_matches,
            recommended_actions=recommended_actions,
            execution_context=execution_context
        )
    
    def _analyze_processes(self) -> List[str]:
        """Analyze running processes for suspicious activity"""
        anomalies = []
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for suspicious process names
            for proc in processes:
                name = proc.get('name', '').lower()
                if any(suspicious in name for suspicious in self.ioc_patterns["suspicious_commands"]):
                    anomalies.append(f"Suspicious process detected: {name}")
                
                # Check command line arguments
                cmdline = proc.get('cmdline', [])
                if cmdline:
                    cmdline_str = ' '.join(cmdline).lower()
                    if any(suspicious in cmdline_str for suspicious in ["download", "execute", "inject", "payload"]):
                        anomalies.append(f"Suspicious command line detected: {cmdline_str[:100]}")
        
        except ImportError:
            # psutil not available, skip process analysis
            pass
        except Exception as e:
            logger.warning(f"Process analysis failed: {e}")
        
        return anomalies
    
    def _analyze_network_activity(self) -> List[str]:
        """Analyze network activity for suspicious patterns"""
        anomalies = []
        try:
            import psutil
            connections = psutil.net_connections()
            
            # Check for unusual number of connections
            if len(connections) > 50:
                anomalies.append(f"High number of network connections: {len(connections)}")
            
            # Check for suspicious remote addresses
            for conn in connections:
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    # Check for private IP ranges that shouldn't be accessed
                    if remote_ip.startswith(('10.', '172.', '192.168.')):
                        continue  # Normal internal traffic
                    
                    # Check for known malicious IP patterns (simplified)
                    if any(pattern in remote_ip for pattern in ['tor', 'malware']):
                        anomalies.append(f"Suspicious remote connection: {remote_ip}")
        
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Network analysis failed: {e}")
        
        return anomalies
    
    def _check_iocs(self) -> List[Dict[str, Any]]:
        """Check for Indicators of Compromise (IOCs)"""
        ioc_matches = []
        
        # Check environment variables for IOCs
        env_data = json.dumps(dict(os.environ))
        for suspicious_term in self.ioc_patterns["suspicious_networks"]:
            if suspicious_term in env_data.lower():
                ioc_matches.append({
                    "type": "environment_variable",
                    "indicator": suspicious_term,
                    "confidence": 0.7,
                    "description": f"Suspicious term '{suspicious_term}' found in environment"
                })
        
        # Check for known malware file hashes (if files accessible)
        try:
            current_hash = self._calculate_code_hash()
            if current_hash in self.ioc_patterns["known_malware_hashes"]:
                ioc_matches.append({
                    "type": "file_hash",
                    "indicator": current_hash,
                    "confidence": 0.95,
                    "description": "Known malware file hash detected"
                })
        except Exception:
            pass
        
        return ioc_matches
    
    def _get_recommended_actions(self, threat_level: ThreatLevel, 
                               anomalies: List[str], ioc_matches: List[Dict[str, Any]]) -> List[str]:
        """Generate recommended security actions based on threat assessment"""
        actions = []
        
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            actions.extend([
                "Immediately isolate the function/container",
                "Rotate all secrets and credentials",
                "Preserve execution environment for forensic analysis",
                "Notify security team immediately"
            ])
        
        if threat_level == ThreatLevel.CRITICAL:
            actions.extend([
                "Initiate incident response procedure",
                "Create forensic memory dump",
                "Block all network egress",
                "Escalate to security operations center"
            ])
        
        if ioc_matches:
            actions.append("Run full malware scan on deployment pipeline")
            actions.append("Check threat intelligence feeds for additional IOCs")
        
        if any("memory" in anomaly.lower() for anomaly in anomalies):
            actions.append("Monitor for memory-based attacks")
        
        if any("network" in anomaly.lower() for anomaly in anomalies):
            actions.append("Analyze network traffic patterns")
            actions.append("Check firewall and VPC logs")
        
        return actions


class SecurityEventLogger:
    """Enhanced security event logging with threat context"""
    
    def __init__(self, logger_name: str = "mcspm.security"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
    
    def log_threat_assessment(self, assessment: ThreatAssessment, context: Dict[str, Any]):
        """Log comprehensive threat assessment results"""
        security_event = {
            "event_type": "threat_assessment",
            "timestamp": time.time(),
            "threat_level": assessment.threat_level.value,
            "risk_score": assessment.risk_score,
            "anomaly_count": len(assessment.anomalies),
            "ioc_matches": len(assessment.ioc_matches),
            "execution_context": assessment.execution_context,
            "function_context": {
                "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("FUNCTION_NAME"),
                "region": os.environ.get("AWS_REGION") or os.environ.get("FUNCTION_REGION"),
                "account_id": context.get("account_id"),
                "project_id": context.get("project_id")
            },
            "anomalies": assessment.anomalies,
            "recommended_actions": assessment.recommended_actions
        }
        
        # Remove sensitive data
        sanitized_event = self._sanitize_security_event(security_event)
        
        # Log with appropriate level based on threat
        if assessment.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            self.logger.error(json.dumps(sanitized_event))
        elif assessment.threat_level == ThreatLevel.MEDIUM:
            self.logger.warning(json.dumps(sanitized_event))
        else:
            self.logger.info(json.dumps(sanitized_event))
    
    def _sanitize_security_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from security events"""
        # Create a deep copy to avoid modifying original
        import copy
        sanitized = copy.deepcopy(event)
        
        # Remove or mask sensitive fields
        sensitive_keys = ["token", "password", "secret", "key", "credential"]
        
        def sanitize_recursive(obj):
            if isinstance(obj, dict):
                return {
                    k: "[REDACTED]" if any(sensitive in k.lower() for sensitive in sensitive_keys)
                    else sanitize_recursive(v) for k, v in obj.items()
                }
            elif isinstance(obj, list):
                return [sanitize_recursive(item) for item in obj]
            else:
                return obj
        
        return sanitize_recursive(sanitized)