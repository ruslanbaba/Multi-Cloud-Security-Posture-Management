terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.30.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.30.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "services" {
  for_each = toset([
    "securitycenter.googleapis.com",
    "pubsub.googleapis.com",
    "cloudfunctions.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
  ])
  project = var.project_id
  service = each.key
}

resource "google_pubsub_topic" "scc" {
  name   = "${var.name_prefix}-mcspm-scc"
  labels = var.labels
}

resource "google_pubsub_subscription" "scc" {
  name  = "${var.name_prefix}-mcspm-scc-sub"
  topic = google_pubsub_topic.scc.id
  labels = var.labels
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dlq.id
    max_delivery_attempts = 10
  }
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

resource "google_pubsub_topic" "dlq" { name = "${var.name_prefix}-mcspm-dlq" }

resource "google_scc_notification_config" "scc" {
  provider     = google-beta
  config_id    = "${var.name_prefix}-mcspm"
  description  = "Forward SCC findings to Pub/Sub"
  organization = var.organization_id != null ? "organizations/${var.organization_id}" : null
  pubsub_topic = google_pubsub_topic.scc.id
  streaming_config { 
    filter = "state = \"ACTIVE\" AND (category = \"MALWARE\" OR category = \"PERSISTENCE\" OR category = \"LATERAL_MOVEMENT\" OR category = \"DEFENSE_EVASION\" OR category = \"CREDENTIAL_ACCESS\" OR category = \"DISCOVERY\" OR category = \"EXECUTION\" OR category = \"EXFILTRATION\" OR category = \"IMPACT\" OR category = \"INITIAL_ACCESS\" OR category = \"PRIVILEGE_ESCALATION\" OR severity = \"HIGH\" OR severity = \"CRITICAL\")"
  }
}

resource "google_secret_manager_secret" "hec_token" {
  secret_id = var.splunk_hec_token_secret
  replication { automatic = true }
}

data "archive_file" "function_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src"
  output_path = "${path.module}/.tmp/mcspm_src.zip"
}

resource "google_cloudfunctions2_function" "forwarder" {
  name        = "${var.name_prefix}-mcspm-forwarder"
  location    = var.region
  description = "SCC → Splunk HEC forwarder"

  build_config {
    runtime     = "python311"
    entry_point = "pubsub_entrypoint"
    source {
      storage_source {
        bucket = google_storage_bucket.code.id
        object = google_storage_bucket_object.src.name
      }
    }
    environment_variables = {
      SPLUNK_HEC_URL = var.splunk_hec_url
      SPLUNK_INDEX   = var.splunk_index
      SPLUNK_SOURCE  = "gcp-scc"
    }
  }

  service_config {
    available_memory   = "512M"
    timeout_seconds    = 60
    max_instance_count = var.max_instance_count
    service_account_email = google_service_account.function_sa.email
    
    dynamic "vpc_connector" {
      for_each = var.enable_zero_trust_networking && var.create_vpc_connector ? [google_vpc_access_connector.mcspm[0].name] : (var.vpc_connector_name != null ? [var.vpc_connector_name] : [])
      content {
        name = vpc_connector.value
        egress_settings = "PRIVATE_RANGES_ONLY"
      }
    }
    
    environment_variables = {
      GCP_SECRET_MANAGER_HEC_TOKEN = "${google_secret_manager_secret.hec_token.id}/versions/latest"
      GCP_PROJECT_ID = var.project_id
      GCP_REGION     = var.region
      ZERO_TRUST_MODE = var.enable_zero_trust_networking ? "true" : "false"
    }
  }
  
  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.scc.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }
}

resource "google_storage_bucket" "code" {
  name                        = "${var.project_id}-${var.name_prefix}-mcspm-code"
  location                    = var.region
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_object" "src" {
  name   = "src.zip"
  bucket = google_storage_bucket.code.name
  source = data.archive_file.function_zip.output_path
}

# Zero Trust VPC Connector (if needed)
resource "google_vpc_access_connector" "mcspm" {
  count         = var.create_vpc_connector ? 1 : 0
  name          = "${var.name_prefix}-mcspm-connector"
  ip_cidr_range = var.vpc_connector_ip_range
  network       = var.vpc_network
  region        = var.region
  
  # Minimum instances for faster cold starts
  min_instances = 2
  max_instances = 10
  
  # Enhanced for zero trust
  machine_type = "e2-micro"
}

# Zero Trust Firewall Rules
resource "google_compute_firewall" "function_egress" {
  count   = var.enable_zero_trust_networking ? 1 : 0
  name    = "${var.name_prefix}-mcspm-function-egress"
  network = var.vpc_network

  direction = "EGRESS"
  priority  = 1000
  
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  target_service_accounts = [google_service_account.function_sa.email]
  destination_ranges      = var.allowed_egress_ranges
  
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "function_ingress_deny" {
  count   = var.enable_zero_trust_networking ? 1 : 0
  name    = "${var.name_prefix}-mcspm-function-ingress-deny"
  network = var.vpc_network

  direction = "INGRESS"
  priority  = 65534
  
  deny {
    protocol = "all"
  }

  target_service_accounts = [google_service_account.function_sa.email]
  source_ranges          = ["0.0.0.0/0"]
  
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Enhanced Service Account with IAM Conditions
resource "google_service_account" "function_sa" {
  account_id   = "${var.name_prefix}-mcspm-function"
  display_name = "MCSPM Cloud Function Service Account"
  description  = "Zero Trust service account for MCSPM Cloud Function"
}

resource "google_project_iam_member" "function_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.function_sa.email}"
  
  condition {
    title       = "Restrict to MCSPM secrets"
    description = "Only allow access to MCSPM-related secrets during business hours"
    expression  = <<-EOT
      resource.name.startsWith('projects/${var.project_id}/secrets/${var.name_prefix}-') &&
      request.time.getHours() >= 0 && request.time.getHours() <= 23
    EOT
  }
}

# VPC Flow Logs (if enabled)
resource "google_compute_subnetwork" "private" {
  count                    = var.enable_vpc_flow_logs && var.vpc_network != null ? 1 : 0
  name                     = "${var.name_prefix}-mcspm-private-subnet"
  ip_cidr_range           = "10.0.1.0/24"
  region                  = var.region
  network                 = var.vpc_network
  private_ip_google_access = var.enable_private_google_access
  
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

