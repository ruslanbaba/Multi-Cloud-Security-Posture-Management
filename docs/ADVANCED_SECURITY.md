# IAM Boundary Policies and Advanced Security

## AWS IAM Permission Boundaries

### Example Boundary Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream", 
        "logs:PutLogEvents",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface",
        "ec2:AttachNetworkInterface",
        "ec2:DetachNetworkInterface"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*",
        "account:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Deployment with Boundary
```hcl
# Create boundary policy
resource "aws_iam_policy" "lambda_boundary" {
  name        = "${var.name_prefix}-mcspm-lambda-boundary"
  description = "Permission boundary for MCSPM Lambda functions"
  policy      = file("${path.module}/policies/lambda_boundary.json")
}

# Use in module
module "aws_mcspm" {
  source = "../../modules/aws"
  # ... other variables
  iam_boundary_policy_arn = aws_iam_policy.lambda_boundary.arn
}
```

## GCP IAM Conditions and Constraints

### Organization Policy Constraints
```yaml
# org-policy-compute-vmExternalIpAccess.yaml
name: projects/PROJECT_ID/policies/compute.vmExternalIpAccess
spec:
  rules:
    - denyAll: true
      condition:
        expression: resource.matchTag('environment', 'production')
```

### Service Account with Conditions
```hcl
resource "google_service_account" "function_sa" {
  account_id   = "${var.name_prefix}-mcspm-function"
  display_name = "MCSPM Cloud Function Service Account"
}

resource "google_project_iam_member" "function_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.function_sa.email}"
  
  condition {
    title       = "Restrict to MCSPM secrets"
    description = "Only allow access to MCSPM-related secrets"
    expression  = "resource.name.startsWith('projects/${var.project_id}/secrets/${var.name_prefix}-')"
  }
}
```

## KMS Key Management

### AWS Customer Managed Keys
```hcl
resource "aws_kms_key" "mcspm" {
  description = "KMS key for ${var.name_prefix} MCSPM encryption"
  key_usage   = "ENCRYPT_DECRYPT"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowLambdaDecryption"
        Effect = "Allow"
        Principal = { AWS = aws_iam_role.lambda.arn }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "secretsmanager.${var.region}.amazonaws.com",
              "logs.${var.region}.amazonaws.com"
            ]
          }
        }
      },
      {
        Sid    = "AllowSecretsManagerAccess"
        Effect = "Allow"
        Principal = { Service = "secretsmanager.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = var.tags
}

# Encrypt Secrets Manager secret with CMK
resource "aws_secretsmanager_secret" "hec_token" {
  name        = "${var.name_prefix}-mcspm-splunk-hec-token"
  description = "Splunk HEC token for MCSPM"
  kms_key_id  = aws_kms_key.mcspm.arn
  
  tags = var.tags
}
```

### GCP Customer Managed Encryption Keys
```hcl
resource "google_kms_key_ring" "mcspm" {
  name     = "${var.name_prefix}-mcspm"
  location = var.region
}

resource "google_kms_crypto_key" "mcspm" {
  name     = "mcspm-encryption-key"
  key_ring = google_kms_key_ring.mcspm.id
  purpose  = "ENCRYPT_DECRYPT"
  
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "function_decrypter" {
  crypto_key_id = google_kms_crypto_key.mcspm.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.function_sa.email}"
}

# Use CMEK for Secret Manager
resource "google_secret_manager_secret" "hec_token" {
  secret_id = var.splunk_hec_token_secret
  
  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.mcspm.id
        }
      }
    }
  }
}
```

## Security Monitoring and Compliance

### AWS CloudTrail Integration
```hcl
resource "aws_cloudtrail" "mcspm_audit" {
  name           = "${var.name_prefix}-mcspm-audit"
  s3_bucket_name = aws_s3_bucket.audit_logs.bucket
  
  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []
    
    data_resource {
      type   = "AWS::SecretsManager::Secret"
      values = [var.splunk_hec_token_secret_arn]
    }
    
    data_resource {
      type   = "AWS::KMS::Key"
      values = [aws_kms_key.mcspm.arn]
    }
  }
  
  tags = var.tags
}
```

### GCP Audit Logging Configuration
```hcl
resource "google_logging_project_sink" "mcspm_audit" {
  name        = "${var.name_prefix}-mcspm-audit-sink"
  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/${google_pubsub_topic.audit.name}"
  
  filter = <<EOF
(protoPayload.serviceName="secretmanager.googleapis.com" AND 
 protoPayload.resourceName:"${google_secret_manager_secret.hec_token.id}") OR
(protoPayload.serviceName="cloudfunctions.googleapis.com" AND 
 protoPayload.resourceName:"${google_cloudfunctions2_function.forwarder.name}")
EOF
  
  unique_writer_identity = true
}
```

## Runtime Security

### Lambda Environment Variable Encryption
```hcl
# In aws_lambda_function resource
environment {
  variables = {
    SPLUNK_HEC_URL    = var.splunk_hec_url
    AWS_SECRETS_MANAGER_HEC_TOKEN_ARN = var.splunk_hec_token_secret_arn
    # Other variables...
  }
}

# KMS key for environment variable encryption
kms_key_arn = var.create_kms_key ? aws_kms_key.lambda[0].arn : var.lambda_kms_key_arn
```

### Function Identity Verification
```python
# In Lambda/Function code - verify execution context
import os
import json

def verify_execution_context():
    """Verify the function is running in expected environment"""
    expected_account = os.environ.get('AWS_ACCOUNT_ID')
    expected_region = os.environ.get('AWS_REGION')
    
    # Add runtime security checks
    if not expected_account or not expected_region:
        raise ValueError("Missing required environment context")
    
    # Log security context (without sensitive data)
    logger.info("Execution context verified", extra={
        "account_id": expected_account,
        "region": expected_region,
        "execution_role": os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
    })
```

## Compliance Frameworks

### SOC 2 Type II Controls
- **CC6.1**: Logical access controls restrict access to authorized users
- **CC6.2**: System limits access through boundary protection
- **CC6.3**: System protects against unauthorized access

### NIST Cybersecurity Framework
- **ID.AM-2**: Software platforms are inventoried (Lambda/Function tracking)
- **PR.AC-4**: Access permissions are managed (IAM policies)
- **PR.DS-1**: Data-at-rest is protected (KMS encryption)
- **DE.AE-2**: Detected events are analyzed (CloudTrail/Audit logs)