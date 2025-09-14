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
    
    dynamic "vpc_connector" {
      for_each = var.vpc_connector_name != null ? [var.vpc_connector_name] : []
      content {
        name = vpc_connector.value
      }
    }
    
    environment_variables = {
      GCP_SECRET_MANAGER_HEC_TOKEN = "${google_secret_manager_secret.hec_token.id}/versions/latest"
      GCP_PROJECT_ID = var.project_id
      GCP_REGION     = var.region
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

