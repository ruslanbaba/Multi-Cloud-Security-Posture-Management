# Enhanced MCSPM Configuration Examples

## Environment Variables Reference

```bash
# Core Configuration
export SPLUNK_HEC_URL="https://splunk.example.com:8088/services/collector"
export SPLUNK_HEC_TOKEN="your-hec-token-here"
export SPLUNK_HEC_INDEX="security"
export SPLUNK_HEC_SOURCE="mcspm"
export SPLUNK_HEC_SOURCETYPE="aws:securityhub"

# Security Features
export ENABLE_ZERO_TRUST="true"
export ENABLE_RUNTIME_SECURITY="true"
export ENABLE_ML_DLP="true"
export ENABLE_AUTOMATED_RESPONSE="true"

# AWS Configuration
export AWS_REGION="us-east-1"
export AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
export AWS_SECRETS_MANAGER_HEC_TOKEN_ARN="arn:aws:secretsmanager:us-east-1:123456789012:secret:splunk-hec-token"
export VPC_ID="vpc-12345678"
export PRIVATE_SUBNET_IDS="subnet-12345678,subnet-87654321"

# GCP Configuration
export GCP_PROJECT_ID="my-security-project"
export GCP_REGION="us-central1"
export GCP_KMS_KEY_NAME="projects/my-security-project/locations/us-central1/keyRings/mcspm/cryptoKeys/encryption-key"
export FUNCTION_NAME="mcspm-forwarder"

# DLP Configuration
export DLP_CONFIDENCE_THRESHOLD="0.8"
export DLP_ENABLE_ML_DETECTION="true"
export DLP_BATCH_SIZE="1000"
export DLP_PARALLEL_PROCESSING="true"

# Runtime Security Configuration
export ANOMALY_THRESHOLD="0.7"
export IOC_FEEDS="aws_guardduty,custom_threat_intel"
export ENABLE_BEHAVIORAL_ANALYSIS="true"

# Incident Response Configuration
export ESCALATION_THRESHOLD="70"
export NOTIFICATION_CHANNELS="sns,email,slack"
export INCIDENT_RESPONSE_TEAM="security-team@company.com"
export FORENSIC_RETENTION_DAYS="90"
```

## Terraform Configuration Examples

### AWS Security Variables

```hcl
# aws/terraform.tfvars
aws_region = "us-east-1"
environment = "production"

# Zero Trust Configuration
enable_zero_trust = true
enable_vpc_endpoints = true
enable_flow_logs = true

# Network Configuration
vpc_cidr = "10.0.0.0/16"
private_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24"]
availability_zones = ["us-east-1a", "us-east-1b"]

# Security Configuration
lambda_timeout = 300
lambda_memory_size = 512
lambda_reserved_concurrency = 10

# Encryption Configuration
kms_key_deletion_window = 7
enable_key_rotation = true

# Monitoring Configuration
enable_cloudwatch_logs = true
log_retention_in_days = 30
enable_xray_tracing = true

# Security Groups
zero_trust_ingress_rules = []
zero_trust_egress_rules = [
  {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound"
  },
  {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "DNS resolution"
  }
]
```

### GCP Security Variables

```hcl
# gcp/terraform.tfvars
gcp_project_id = "my-security-project"
gcp_region = "us-central1"
environment = "production"

# Zero Trust Configuration
enable_zero_trust = true
enable_vpc_connector = true
enable_private_google_access = true

# Network Configuration
vpc_network = "mcspm-vpc"
vpc_subnet_cidr = "10.1.0.0/24"
connector_cidr = "10.8.0.0/28"

# Security Configuration
function_timeout = 300
function_memory = 512
function_max_instances = 10

# Encryption Configuration
kms_key_rotation_period = "7776000s" # 90 days
kms_protection_level = "SOFTWARE"

# Monitoring Configuration
enable_cloud_logging = true
log_retention_days = 30
enable_cloud_trace = true

# Firewall Rules
zero_trust_firewall_rules = [
  {
    name      = "zero-trust-https-egress"
    direction = "EGRESS"
    priority  = 1000
    target_tags = ["zero-trust-function"]
    allowed = [
      {
        protocol = "tcp"
        ports    = ["443"]
      }
    ]
  }
]
```

## Security Policy Examples

### DLP Rules Configuration

```json
{
  "dlp_rules": {
    "credit_card": {
      "enabled": true,
      "pattern": "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b",
      "confidence_threshold": 0.9,
      "action": "MASK",
      "severity": "HIGH"
    },
    "ssn": {
      "enabled": true,
      "pattern": "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b",
      "confidence_threshold": 0.95,
      "action": "BLOCK",
      "severity": "CRITICAL"
    },
    "email": {
      "enabled": true,
      "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
      "confidence_threshold": 0.8,
      "action": "ALERT",
      "severity": "MEDIUM"
    },
    "phone": {
      "enabled": true,
      "pattern": "\\b(?:\\+?1[-.]?)?\\(?([0-9]{3})\\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\\b",
      "confidence_threshold": 0.8,
      "action": "MASK",
      "severity": "MEDIUM"
    },
    "api_key": {
      "enabled": true,
      "pattern": "\\b[A-Za-z0-9]{32,}\\b",
      "confidence_threshold": 0.85,
      "action": "BLOCK",
      "severity": "HIGH"
    }
  },
  "ml_detection": {
    "enabled": true,
    "confidence_threshold": 0.8,
    "models": ["pii_classifier", "sensitive_data_detector"]
  }
}
```

### Incident Response Playbooks

```json
{
  "incident_response_playbooks": {
    "MALWARE_DETECTION": {
      "severity_mapping": {
        "HIGH": "CRITICAL",
        "MEDIUM": "HIGH"
      },
      "automated_actions": [
        "isolate_function",
        "preserve_evidence",
        "block_execution",
        "notify_security_team"
      ],
      "escalation_rules": {
        "CRITICAL": ["security_team", "executives", "incident_commander"],
        "HIGH": ["security_team", "on_call_engineer"]
      },
      "containment_timeout": 300
    },
    "DLP_VIOLATION": {
      "severity_mapping": {
        "CRITICAL": "HIGH",
        "HIGH": "MEDIUM"
      },
      "automated_actions": [
        "block_transmission",
        "sanitize_data",
        "log_violation",
        "notify_compliance_team"
      ],
      "data_retention": {
        "evidence": "90_days",
        "logs": "7_years"
      }
    },
    "CREDENTIAL_COMPROMISE": {
      "severity_mapping": {
        "ANY": "CRITICAL"
      },
      "automated_actions": [
        "rotate_secrets",
        "invalidate_sessions",
        "enable_monitoring",
        "notify_security_team"
      ],
      "immediate_response": true,
      "max_response_time": 60
    }
  }
}
```

### Zero Trust Network Policies

```json
{
  "zero_trust_policies": {
    "network_segmentation": {
      "default_deny": true,
      "allowed_services": [
        {
          "service": "secretsmanager",
          "protocol": "https",
          "port": 443,
          "conditions": ["environment_tag", "function_role"]
        },
        {
          "service": "kms",
          "protocol": "https",
          "port": 443,
          "conditions": ["encryption_key_access"]
        }
      ]
    },
    "identity_verification": {
      "require_mfa": true,
      "session_timeout": 3600,
      "continuous_verification": true
    },
    "device_trust": {
      "require_managed_device": true,
      "certificate_based_auth": true,
      "device_compliance_check": true
    }
  }
}
```

## Monitoring and Alerting Configuration

### CloudWatch Alarms (AWS)

```json
{
  "cloudwatch_alarms": {
    "high_threat_detection": {
      "metric_name": "ThreatLevel",
      "namespace": "MCSPM/Security",
      "statistic": "Maximum",
      "period": 300,
      "evaluation_periods": 1,
      "threshold": 80,
      "comparison_operator": "GreaterThanThreshold",
      "alarm_actions": ["arn:aws:sns:us-east-1:123456789012:security-alerts"]
    },
    "dlp_violations": {
      "metric_name": "DLPViolations",
      "namespace": "MCSPM/DataProtection",
      "statistic": "Sum",
      "period": 300,
      "evaluation_periods": 2,
      "threshold": 5,
      "comparison_operator": "GreaterThanThreshold"
    },
    "function_errors": {
      "metric_name": "Errors",
      "namespace": "AWS/Lambda",
      "dimensions": {
        "FunctionName": "mcspm-forwarder"
      },
      "statistic": "Sum",
      "period": 300,
      "evaluation_periods": 2,
      "threshold": 10,
      "comparison_operator": "GreaterThanThreshold"
    }
  }
}
```

### Cloud Monitoring (GCP)

```yaml
# monitoring.yaml
alertPolicy:
  displayName: "MCSPM High Threat Detection"
  conditions:
    - displayName: "High threat level detected"
      conditionThreshold:
        filter: 'resource.type="cloud_function" AND metric.type="custom.googleapis.com/mcspm/threat_level"'
        comparison: COMPARISON_GREATER_THAN
        thresholdValue: 80
        duration: "300s"
  notificationChannels:
    - "projects/my-project/notificationChannels/security-alerts"
  
---
alertPolicy:
  displayName: "MCSPM DLP Violations"
  conditions:
    - displayName: "DLP violations detected"
      conditionThreshold:
        filter: 'resource.type="cloud_function" AND metric.type="custom.googleapis.com/mcspm/dlp_violations"'
        comparison: COMPARISON_GREATER_THAN
        thresholdValue: 5
        duration: "300s"
        aggregations:
          - alignmentPeriod: "300s"
            perSeriesAligner: ALIGN_RATE
```

## Performance Tuning

### Memory Optimization

```python
# config/performance.py
PERFORMANCE_CONFIG = {
    "dlp_scanner": {
        "batch_size": 1000,
        "parallel_processing": True,
        "cache_size": 10000,
        "memory_limit_mb": 256
    },
    "encryption": {
        "chunk_size": 1048576,  # 1MB chunks
        "compression_enabled": True,
        "streaming_threshold": 10485760  # 10MB
    },
    "runtime_security": {
        "analysis_timeout": 30,
        "cache_ttl": 300,
        "max_events": 1000
    }
}
```

### Function Configuration

```bash
# AWS Lambda Configuration
aws lambda update-function-configuration \
  --function-name mcspm-forwarder \
  --timeout 300 \
  --memory-size 512 \
  --reserved-concurrent-executions 10 \
  --environment Variables='{
    "ENABLE_ZERO_TRUST":"true",
    "ENABLE_ML_DLP":"true",
    "DLP_BATCH_SIZE":"1000",
    "ANOMALY_THRESHOLD":"0.7"
  }'

# GCP Cloud Function Configuration
gcloud functions deploy mcspm-forwarder \
  --runtime python39 \
  --timeout 300s \
  --memory 512MB \
  --max-instances 10 \
  --set-env-vars "ENABLE_ZERO_TRUST=true,ENABLE_ML_DLP=true"
```

## Testing Configuration

### Unit Test Environment

```bash
# test/.env
SPLUNK_HEC_URL="http://localhost:8088/services/collector"
SPLUNK_HEC_TOKEN="test-token"
ENABLE_ZERO_TRUST="false"
ENABLE_ML_DLP="false"
AWS_REGION="us-east-1"
GCP_REGION="us-central1"
```

### Integration Test Setup

```python
# tests/integration/test_config.py
TEST_CONFIG = {
    "aws": {
        "region": "us-east-1",
        "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "vpc_id": "vpc-test123",
        "subnet_ids": ["subnet-test123"]
    },
    "gcp": {
        "project_id": "test-project",
        "region": "us-central1",
        "kms_key_name": "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/test"
    },
    "security": {
        "enable_dlp": True,
        "enable_runtime_security": True,
        "threat_threshold": 50
    }
}
```

## Quick Start Commands

```bash
# Clone repository
git clone https://github.com/your-org/mcspm-enhanced.git
cd mcspm-enhanced

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Test configuration
python scripts/test_config.py

# Deploy infrastructure
cd infra/terraform/modules/aws
terraform init && terraform apply

# Deploy functions
cd ../../../../src/aws_lambda_forwarder
zip -r lambda.zip .
aws lambda update-function-code --function-name mcspm-forwarder --zip-file fileb://lambda.zip

# Test deployment
python scripts/test_deployment.py
```