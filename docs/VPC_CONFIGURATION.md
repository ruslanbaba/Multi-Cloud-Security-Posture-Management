# VPC Egress Configuration Examples

## AWS Lambda VPC Configuration

### Private Subnet with NAT Gateway (Recommended)
```hcl
# Example terraform.tfvars for staging environment
vpc_subnet_ids = ["subnet-12345678", "subnet-87654321"]  # Private subnets
vpc_security_group_ids = ["sg-abcdef12"]

# Security group should allow:
# - Outbound HTTPS (443) to Splunk HEC endpoint
# - Outbound HTTPS (443) to AWS APIs (Secrets Manager, etc.)
```

### PrivateLink Endpoints (Enhanced Security)
```hcl
# Create VPC endpoints for AWS services to avoid internet routing
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.secretsmanager"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.lambda_vpc_endpoints.id]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = "*"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = var.splunk_hec_token_secret_arn
    }]
  })
}
```

## GCP Cloud Function VPC Configuration

### Serverless VPC Connector
```hcl
# Create VPC connector for private network access
resource "google_vpc_access_connector" "mcspm" {
  name          = "${var.name_prefix}-mcspm-connector"
  ip_cidr_range = "10.8.0.0/28"  # /28 subnet for connector
  network       = var.vpc_network
  region        = var.region
  
  # Minimum instances for faster cold starts
  min_instances = 2
  max_instances = 10
}

# Use in function deployment
vpc_connector_name = google_vpc_access_connector.mcspm.name
```

### Private Google Access
```hcl
# Enable Private Google Access on subnet
resource "google_compute_subnetwork" "private" {
  name                     = "${var.name_prefix}-private-subnet"
  ip_cidr_range           = "10.0.1.0/24"
  region                  = var.region
  network                 = google_compute_network.vpc.id
  private_ip_google_access = true  # Enable Private Google Access
}
```

## Network Security Considerations

### Egress Filtering
- **AWS**: Use Security Groups to restrict outbound traffic to specific FQDN/IP ranges
- **GCP**: Use firewall rules with target tags to control egress

### DNS Resolution
- **AWS**: Ensure Route 53 resolver or custom DNS can resolve Splunk HEC endpoint
- **GCP**: Verify Cloud DNS or custom DNS configuration

### Monitoring
- **AWS**: Enable VPC Flow Logs to monitor Lambda network traffic
- **GCP**: Enable VPC Flow Logs and Cloud NAT logging for Function traffic

### Example Security Group (AWS)
```hcl
resource "aws_security_group" "lambda_egress" {
  name_prefix = "${var.name_prefix}-mcspm-lambda-"
  vpc_id      = var.vpc_id

  egress {
    description = "HTTPS to Splunk HEC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Restrict to Splunk IP ranges if known
  }

  egress {
    description = "HTTPS to AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}
```

### Example Firewall Rule (GCP)
```hcl
resource "google_compute_firewall" "function_egress" {
  name    = "${var.name_prefix}-mcspm-function-egress"
  network = var.vpc_network

  direction = "EGRESS"
  
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  target_service_accounts = [google_service_account.function.email]
  
  # Restrict to specific destinations if possible
  destination_ranges = ["0.0.0.0/0"]
}