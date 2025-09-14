# Enhanced Multi-Cloud Security Posture Management (MCSPM)

A comprehensive Zero Trust security platform that aggregates, analyzes, and responds to security findings from AWS Security Hub and Google Cloud Security Command Center, with advanced threat detection, data protection, and automated incident response capabilities.

## 🚀 Key Features

### Core Security Posture Management
- **Multi-Cloud Integration**: AWS Security Hub and GCP Security Command Center
- **Real-time Forwarding**: Stream security findings to Splunk HEC
- **Centralized Monitoring**: Unified security dashboard across cloud platforms

### Zero Trust Security Enhancements
- **🛡️ Zero Trust Network Architecture**: Micro-segmentation, private connectivity, identity-centric controls
- **🔍 Runtime Security & Threat Detection**: Behavioral anomaly detection, code integrity verification, threat intelligence integration
- **🔐 Supply Chain Security**: Multi-layered CI/CD scanning, SBOM generation, provenance verification
- **🛡️ Advanced Data Protection**: Enhanced DLP with ML detection, envelope encryption, field-level encryption
- **🚨 Automated Incident Response**: SOAR integration, digital forensics, automated containment

## 📋 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Zero Trust Security Platform                  │
├─────────────────────────────────────────────────────────────────┤
│  🚨 Automated Incident Response (SOAR Integration)              │
├─────────────────────────────────────────────────────────────────┤
│  🛡️ Advanced Data Protection (DLP + Encryption)                 │
├─────────────────────────────────────────────────────────────────┤
│  🔐 Supply Chain Security (SBOM + Provenance)                   │
├─────────────────────────────────────────────────────────────────┤
│  🔍 Runtime Security & Threat Detection                         │
├─────────────────────────────────────────────────────────────────┤
│  🛡️ Zero Trust Network Architecture                             │
├─────────────────────────────────────────────────────────────────┤
│  📊 Multi-Cloud Security Posture Management (Core)              │
└─────────────────────────────────────────────────────────────────┘
```

## 🔒 Security Components

### 1. Zero Trust Network Architecture
- **Micro-segmentation**: VPC endpoints, security groups, firewall rules
- **Private Connectivity**: Secure service-to-service communication
- **Network Monitoring**: VPC flow logs, connection analysis
- **Identity-Centric Controls**: Conditional access policies

### 2. Runtime Security & Threat Detection
- **Behavioral Analysis**: Execution pattern anomaly detection
- **Code Integrity**: Runtime code verification and memory protection
- **Threat Intelligence**: IOC matching and threat assessment
- **Risk Scoring**: Dynamic risk calculation based on multiple factors

### 3. Supply Chain Security
- **Multi-layered Scanning**: CodeQL, Semgrep, Trivy integration
- **SBOM Generation**: Software Bill of Materials for transparency
- **Provenance Verification**: SLSA framework implementation
- **Security Gates**: Automated security approval workflow

### 4. Advanced Data Protection
- **Enhanced DLP**: 15+ detection rules with ML-powered classification
- **Envelope Encryption**: Scalable encryption for large payloads using cloud KMS
- **Field-Level Encryption**: Selective encryption of sensitive data fields
- **Data Sanitization**: Automated data masking and blocking

### 5. Automated Incident Response
- **SOAR Integration**: Automated incident creation and response
- **Digital Forensics**: Evidence preservation and chain of custody
- **Threat Hunting**: Proactive threat detection and IOC analysis
- **Automated Containment**: Function isolation, traffic blocking, secret rotation
- Extensible mappings: Shared Python library maps cloud findings to Splunk CIM-like fields
- CI and quality: Linting, typing, unit tests, terraform fmt/validate, security policy

## Repository Layout

```
infra/
  terraform/
    modules/
      aws/          # AWS Lambda, EventBridge, Security Hub, KMS, VPC support
## 🛠️ Quick Start

### Prerequisites
- AWS Account with Security Hub enabled
- GCP Project with Security Command Center enabled
- Splunk instance with HEC endpoint
- Terraform >= 1.0
- Python 3.9+

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/mcspm-enhanced.git
   cd mcspm-enhanced
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Deploy infrastructure**
   ```bash
   cd infra/terraform/modules/aws
   terraform init && terraform apply
   
   cd ../gcp
   terraform init && terraform apply
   ```

5. **Deploy functions**
   ```bash
   # AWS Lambda
   cd src/aws_lambda_forwarder
   zip -r lambda.zip .
   aws lambda update-function-code --function-name mcspm-forwarder --zip-file fileb://lambda.zip
   
   # GCP Cloud Function
   cd ../gcp_function_forwarder
   gcloud functions deploy mcspm-forwarder --runtime python39 --trigger-topic security-findings
   ```

## ⚙️ Configuration

### Environment Variables

```bash
# Core Configuration
export SPLUNK_HEC_URL="https://splunk.example.com:8088/services/collector"
export SPLUNK_HEC_TOKEN="your-token-here"

# Security Features
export ENABLE_ZERO_TRUST="true"
export ENABLE_RUNTIME_SECURITY="true"
export ENABLE_ML_DLP="true"
export ENABLE_AUTOMATED_RESPONSE="true"

# AWS Configuration
export AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789012:key/..."
export VPC_ID="vpc-12345678"

# GCP Configuration
export GCP_KMS_KEY_NAME="projects/.../locations/.../keyRings/.../cryptoKeys/..."
```

For detailed configuration options, see [Configuration Examples](docs/CONFIGURATION_EXAMPLES.md).

## 📖 Documentation

- [🔒 Security Enhancement Guide](docs/SECURITY_ENHANCEMENT_GUIDE.md) - Comprehensive security feature documentation
- [⚙️ Configuration Examples](docs/CONFIGURATION_EXAMPLES.md) - Ready-to-use configuration templates
- [🚀 Deployment Guide](docs/SECURITY_ENHANCEMENT_GUIDE.md#deployment-guide) - Step-by-step deployment instructions
- [🔧 Troubleshooting](docs/SECURITY_ENHANCEMENT_GUIDE.md#troubleshooting) - Common issues and solutions

## 🔍 Monitoring & Alerting

### Security Metrics
- Threat detection rate and accuracy
- DLP violation frequency and patterns
- Incident response time and effectiveness
- Risk score trends and patterns

### Alert Thresholds
- **Critical Incidents**: Immediate notification
- **High Risk Scores**: 15-minute alert
- **DLP Violations**: Real-time alert
- **Runtime Anomalies**: 5-minute alert

### Dashboard Views
- Security posture overview
- Threat landscape analysis
- Incident response status
- Compliance metrics

## 🧪 Testing

```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Test security components
python scripts/test_security.py

# Validate configuration
python scripts/test_config.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run security scans
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Security Enhancement Guide](docs/SECURITY_ENHANCEMENT_GUIDE.md)
- **Issues**: GitHub Issues
- **Security**: security-team@company.com
- **Emergency**: +1-555-SECURITY

## 🔄 Version History

- **v2.0.0** - Zero Trust Security Platform with automated incident response
- **v1.5.0** - Advanced data protection and supply chain security
- **v1.0.0** - Initial multi-cloud security posture management

---

**⚠️ Security Notice**: This platform handles sensitive security data. Ensure proper access controls, encryption, and monitoring are in place before production deployment.

**📞 Emergency Response**: For critical security incidents, contact the security team immediately at security-team@company.com or +1-555-SECURITY.
