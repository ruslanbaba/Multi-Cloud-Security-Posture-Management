from __future__ import annotations

import re
import json
import hashlib
import logging
from typing import Dict, Any, List, Tuple, Optional, Union
from dataclasses import dataclass
from enum import Enum
import base64

logger = logging.getLogger(__name__)


class DLPSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DLPAction(Enum):
    ALERT = "alert"
    MASK = "mask"
    BLOCK = "block"
    ENCRYPT = "encrypt"


@dataclass
class DLPRule:
    name: str
    pattern: re.Pattern
    severity: DLPSeverity
    action: DLPAction
    confidence_threshold: float = 0.8
    description: str = ""


@dataclass
class DLPViolation:
    rule_name: str
    severity: DLPSeverity
    action: DLPAction
    matches: int
    confidence: float
    sample: str
    context: str
    remediation: str


class EnhancedDLPScanner:
    """Advanced Data Loss Prevention scanner with ML-based pattern detection"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.rules = self._initialize_dlp_rules()
        self.ml_enabled = self.config.get("enable_ml_detection", False)
        
    def _initialize_dlp_rules(self) -> List[DLPRule]:
        """Initialize comprehensive DLP rules for cloud security data"""
        return [
            # Cloud Credentials (Critical)
            DLPRule(
                name="aws_access_key",
                pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
                severity=DLPSeverity.CRITICAL,
                action=DLPAction.BLOCK,
                description="AWS Access Key ID detected"
            ),
            DLPRule(
                name="aws_secret_key",
                pattern=re.compile(r'[A-Za-z0-9/+=]{40}'),
                severity=DLPSeverity.CRITICAL,
                action=DLPAction.BLOCK,
                confidence_threshold=0.9,
                description="Potential AWS Secret Access Key"
            ),
            DLPRule(
                name="gcp_api_key",
                pattern=re.compile(r'AIza[0-9A-Za-z_-]{35}'),
                severity=DLPSeverity.CRITICAL,
                action=DLPAction.BLOCK,
                description="Google Cloud API Key detected"
            ),
            DLPRule(
                name="gcp_service_account_key",
                pattern=re.compile(r'"type":\s*"service_account"'),
                severity=DLPSeverity.CRITICAL,
                action=DLPAction.BLOCK,
                description="GCP Service Account Key JSON detected"
            ),
            
            # Private Keys (Critical)
            DLPRule(
                name="private_key",
                pattern=re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
                severity=DLPSeverity.CRITICAL,
                action=DLPAction.BLOCK,
                description="Private key detected"
            ),
            DLPRule(
                name="ssh_private_key",
                pattern=re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
                severity=DLPSeverity.CRITICAL,
                action=DLPAction.BLOCK,
                description="SSH private key detected"
            ),
            
            # Authentication Tokens (High)
            DLPRule(
                name="jwt_token",
                pattern=re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
                severity=DLPSeverity.HIGH,
                action=DLPAction.MASK,
                description="JWT token detected"
            ),
            DLPRule(
                name="bearer_token",
                pattern=re.compile(r'Bearer\s+[A-Za-z0-9_-]{20,}'),
                severity=DLPSeverity.HIGH,
                action=DLPAction.MASK,
                description="Bearer token detected"
            ),
            
            # Personal Information (High/Medium)
            DLPRule(
                name="credit_card",
                pattern=re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
                severity=DLPSeverity.HIGH,
                action=DLPAction.MASK,
                description="Credit card number detected"
            ),
            DLPRule(
                name="ssn",
                pattern=re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
                severity=DLPSeverity.HIGH,
                action=DLPAction.MASK,
                description="Social Security Number detected"
            ),
            DLPRule(
                name="email",
                pattern=re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
                severity=DLPSeverity.MEDIUM,
                action=DLPAction.ALERT,
                description="Email address detected"
            ),
            DLPRule(
                name="phone_number",
                pattern=re.compile(r'\b\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
                severity=DLPSeverity.MEDIUM,
                action=DLPAction.ALERT,
                description="Phone number detected"
            ),
            
            # IP Addresses and URLs (Low/Medium)
            DLPRule(
                name="ipv4_address",
                pattern=re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
                severity=DLPSeverity.LOW,
                action=DLPAction.ALERT,
                description="IPv4 address detected"
            ),
            DLPRule(
                name="url",
                pattern=re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
                severity=DLPSeverity.LOW,
                action=DLPAction.ALERT,
                description="URL detected"
            ),
        ]
    
    def scan_payload(self, data: Union[Dict[str, Any], str, List[Any]]) -> Tuple[bool, List[DLPViolation]]:
        """Comprehensive payload scanning with contextual analysis"""
        violations = []
        
        # Convert data to searchable string format
        if isinstance(data, dict):
            data_str = json.dumps(data, default=str, indent=2)
            context_type = "json_object"
        elif isinstance(data, list):
            data_str = json.dumps(data, default=str, indent=2)
            context_type = "json_array"
        else:
            data_str = str(data)
            context_type = "string"
        
        # Rule-based scanning
        for rule in self.rules:
            matches = rule.pattern.findall(data_str)
            if matches:
                # Calculate confidence based on context
                confidence = self._calculate_confidence(rule, matches, data_str, context_type)
                
                if confidence >= rule.confidence_threshold:
                    violation = DLPViolation(
                        rule_name=rule.name,
                        severity=rule.severity,
                        action=rule.action,
                        matches=len(matches),
                        confidence=confidence,
                        sample=matches[0][:20] + "..." if len(matches[0]) > 20 else matches[0],
                        context=context_type,
                        remediation=self._get_remediation_advice(rule)
                    )
                    violations.append(violation)
        
        # ML-based scanning (if enabled)
        if self.ml_enabled:
            ml_violations = self._ml_pattern_detection(data_str, context_type)
            violations.extend(ml_violations)
        
        return len(violations) > 0, violations
    
    def _calculate_confidence(self, rule: DLPRule, matches: List[str], 
                            data_str: str, context_type: str) -> float:
        """Calculate confidence score for detected patterns"""
        base_confidence = 0.8
        
        # Adjust confidence based on rule type
        if rule.name in ["aws_access_key", "gcp_api_key"]:
            # These have very specific patterns
            base_confidence = 0.95
        elif rule.name == "aws_secret_key":
            # More generic pattern, need context validation
            if "aws" in data_str.lower() or "secret" in data_str.lower():
                base_confidence = 0.9
            else:
                base_confidence = 0.6
        elif rule.name in ["credit_card", "ssn"]:
            # Validate using checksums if possible
            base_confidence = self._validate_financial_data(matches[0], rule.name)
        
        # Adjust based on context
        if context_type == "json_object":
            # JSON context provides more structure
            base_confidence += 0.1
        
        # Check for multiple matches (increases confidence)
        if len(matches) > 1:
            base_confidence = min(0.95, base_confidence + 0.05 * len(matches))
        
        return min(1.0, base_confidence)
    
    def _validate_financial_data(self, value: str, rule_type: str) -> float:
        """Validate financial data using checksums"""
        if rule_type == "credit_card":
            # Luhn algorithm validation
            digits = re.sub(r'[\s-]', '', value)
            if self._luhn_checksum(digits):
                return 0.9
            else:
                return 0.4
        return 0.8
    
    def _luhn_checksum(self, card_num: str) -> bool:
        """Validate credit card using Luhn algorithm"""
        try:
            digits = [int(d) for d in card_num]
            for i in range(len(digits) - 2, -1, -2):
                digits[i] *= 2
                if digits[i] > 9:
                    digits[i] -= 9
            return sum(digits) % 10 == 0
        except (ValueError, IndexError):
            return False
    
    def _ml_pattern_detection(self, data_str: str, context_type: str) -> List[DLPViolation]:
        """ML-based pattern detection (placeholder for future implementation)"""
        # This would integrate with actual ML models for advanced pattern detection
        # For now, return empty list
        return []
    
    def _get_remediation_advice(self, rule: DLPRule) -> str:
        """Get remediation advice for specific violations"""
        remediation_map = {
            "aws_access_key": "Rotate AWS access key immediately and review IAM policies",
            "aws_secret_key": "Rotate AWS secret key immediately and enable AWS CloudTrail",
            "gcp_api_key": "Regenerate GCP API key and restrict API permissions",
            "private_key": "Regenerate private key and review access controls",
            "jwt_token": "Invalidate JWT token and review token expiration policies",
            "credit_card": "Mask credit card data and review PCI DSS compliance",
            "ssn": "Encrypt SSN data and review data retention policies"
        }
        return remediation_map.get(rule.name, "Review data handling practices and apply appropriate controls")
    
    def sanitize_payload(self, data: Union[Dict[str, Any], str, List[Any]], 
                        violations: List[DLPViolation]) -> Union[Dict[str, Any], str, List[Any]]:
        """Sanitize payload based on violation actions"""
        if not violations:
            return data
        
        # Handle different data types
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, default=str, indent=2)
            original_type = type(data)
        else:
            data_str = str(data)
            original_type = str
        
        # Apply sanitization based on violation actions
        for violation in violations:
            if violation.action == DLPAction.BLOCK:
                raise SecurityError(f"Data blocked due to {violation.rule_name} violation: {violation.sample}")
            elif violation.action == DLPAction.MASK:
                data_str = self._apply_masking(data_str, violation)
            elif violation.action == DLPAction.ENCRYPT:
                data_str = self._apply_field_encryption(data_str, violation)
        
        # Convert back to original type
        if original_type in (dict, list):
            try:
                return json.loads(data_str)
            except json.JSONDecodeError:
                logger.warning("Failed to parse sanitized JSON, returning hash")
                return {
                    "sanitized": True,
                    "hash": hashlib.sha256(data_str.encode()).hexdigest()[:16],
                    "violations": len(violations)
                }
        else:
            return data_str
    
    def _apply_masking(self, data_str: str, violation: DLPViolation) -> str:
        """Apply appropriate masking based on violation type"""
        rule_name = violation.rule_name
        
        masking_patterns = {
            "credit_card": (r'\b(\d{4})[\s-]?\d{4}[\s-]?\d{4}[\s-]?(\d{4})\b', r'\1-****-****-\2'),
            "ssn": (r'\b(\d{3})-\d{2}-(\d{4})\b', r'\1-**-\2'),
            "email": (r'\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b', r'***@\2'),
            "phone_number": (r'\b(\+?1?[-.\s]?\(?[0-9]{3}\)?)[-.\s]?[0-9]{3}[-.\s]?([0-9]{4})\b', r'\1-***-\2'),
            "jwt_token": (r'(eyJ[A-Za-z0-9_-]+\.)(eyJ[A-Za-z0-9_-]+)(\.[A-Za-z0-9_-]+)', r'\1[MASKED]\3'),
            "bearer_token": (r'(Bearer\s+)([A-Za-z0-9_-]{20,})', r'\1[MASKED]'),
            "ipv4_address": (r'\b(\d{1,3}\.\d{1,3}\.)\d{1,3}\.\d{1,3}\b', r'\1***.***')
        }
        
        if rule_name in masking_patterns:
            pattern, replacement = masking_patterns[rule_name]
            return re.sub(pattern, replacement, data_str)
        else:
            # Generic masking for other patterns
            return data_str.replace(violation.sample, "[REDACTED]")
    
    def _apply_field_encryption(self, data_str: str, violation: DLPViolation) -> str:
        """Apply field-level encryption (placeholder implementation)"""
        # In production, this would use actual encryption
        encrypted_placeholder = f"[ENCRYPTED:{hashlib.sha256(violation.sample.encode()).hexdigest()[:16]}]"
        return data_str.replace(violation.sample, encrypted_placeholder)


class EnvelopeEncryption:
    """Envelope encryption for large payloads using cloud KMS"""
    
    def __init__(self, provider: str, region: str, key_id: str):
        self.provider = provider
        self.region = region
        self.key_id = key_id
        
    def encrypt_large_payload(self, data: Dict[str, Any], 
                            size_threshold: int = 10000) -> Dict[str, Any]:
        """Encrypt large payloads using envelope encryption"""
        data_str = json.dumps(data, default=str)
        
        if len(data_str.encode()) < size_threshold:
            # Small payload, no envelope encryption needed
            return data
        
        try:
            if self.provider == "aws":
                return self._aws_envelope_encrypt(data_str)
            elif self.provider == "gcp":
                return self._gcp_envelope_encrypt(data_str)
            else:
                logger.warning(f"Unsupported provider for envelope encryption: {self.provider}")
                return data
        except Exception as e:
            logger.error(f"Envelope encryption failed: {e}")
            return data
    
    def _aws_envelope_encrypt(self, data_str: str) -> Dict[str, Any]:
        """AWS KMS envelope encryption"""
        try:
            import boto3
            import os
            from cryptography.fernet import Fernet
            
            kms_client = boto3.client('kms', region_name=self.region)
            
            # Generate data encryption key
            response = kms_client.generate_data_key(
                KeyId=self.key_id,
                KeySpec='AES_256',
                EncryptionContext={
                    'purpose': 'mcspm-envelope',
                    'region': self.region
                }
            )
            
            # Encrypt data with data key
            fernet = Fernet(base64.urlsafe_b64encode(response['Plaintext'][:32]))
            encrypted_data = fernet.encrypt(data_str.encode())
            
            return {
                "encrypted": True,
                "envelope_encryption": {
                    "provider": "aws",
                    "encrypted_data_key": base64.b64encode(response['CiphertextBlob']).decode(),
                    "encrypted_payload": base64.b64encode(encrypted_data).decode(),
                    "key_id": self.key_id,
                    "encryption_context": {
                        "purpose": "mcspm-envelope",
                        "region": self.region
                    }
                }
            }
        except Exception as e:
            logger.error(f"AWS envelope encryption failed: {e}")
            raise
    
    def _gcp_envelope_encrypt(self, data_str: str) -> Dict[str, Any]:
        """GCP KMS envelope encryption"""
        try:
            from google.cloud import kms
            from cryptography.fernet import Fernet
            import os
            
            client = kms.KeyManagementServiceClient()
            key_name = f"projects/{os.environ.get('GCP_PROJECT_ID')}/locations/{self.region}/keyRings/mcspm/cryptoKeys/{self.key_id}"
            
            # Generate data encryption key
            data_key = os.urandom(32)
            
            # Encrypt data key with KMS
            encrypt_response = client.encrypt(
                request={
                    "name": key_name,
                    "plaintext": data_key
                }
            )
            
            # Encrypt data with data key
            fernet = Fernet(base64.urlsafe_b64encode(data_key))
            encrypted_data = fernet.encrypt(data_str.encode())
            
            return {
                "encrypted": True,
                "envelope_encryption": {
                    "provider": "gcp",
                    "encrypted_data_key": base64.b64encode(encrypt_response.ciphertext).decode(),
                    "encrypted_payload": base64.b64encode(encrypted_data).decode(),
                    "key_name": key_name
                }
            }
        except Exception as e:
            logger.error(f"GCP envelope encryption failed: {e}")
            raise


class FieldLevelEncryption:
    """Field-level encryption for sensitive data elements"""
    
    def __init__(self, encryption_key: str):
        try:
            from cryptography.fernet import Fernet
            self.fernet = Fernet(encryption_key.encode() if len(encryption_key.encode()) == 44 else Fernet.generate_key())
        except ImportError:
            logger.warning("cryptography package not available, field-level encryption disabled")
            self.fernet = None
    
    def encrypt_sensitive_fields(self, data: Dict[str, Any], 
                               sensitive_fields: List[str]) -> Dict[str, Any]:
        """Encrypt specified sensitive fields in the data"""
        if not self.fernet:
            return data
        
        encrypted_data = data.copy()
        
        for field in sensitive_fields:
            if field in encrypted_data:
                try:
                    field_value = str(encrypted_data[field])
                    encrypted_value = self.fernet.encrypt(field_value.encode())
                    encrypted_data[field] = base64.b64encode(encrypted_value).decode()
                    encrypted_data[f"{field}_encrypted"] = True
                except Exception as e:
                    logger.error(f"Failed to encrypt field {field}: {e}")
        
        return encrypted_data


class SecurityError(Exception):
    """Custom exception for data protection violations"""
    pass