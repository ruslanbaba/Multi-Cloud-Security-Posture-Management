terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.28"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.28"
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

resource "google_pubsub_topic" "scc_findings" {
  name   = "${var.name_prefix}-mcspm-scc"
  labels = var.labels
}

resource "google_pubsub_subscription" "scc_sub" {
  name  = "${var.name_prefix}-mcspm-scc-sub"
  topic = google_pubsub_topic.scc_findings.name
  ack_deadline_seconds = 30
  labels = var.labels
}

resource "google_scc_source" "custom" {
  count   = 0 # not creating sources; relying on SCC default sources
  display_name = "placeholder"
}

resource "google_scc_notification_config" "config" {
  count       = var.enable_notification ? 1 : 0
  provider    = google-beta
  config_id   = "${var.name_prefix}-mcspm-config"
  organization = "organizations/1234567890" # to be set by consumer
  pubsub_topic = google_pubsub_topic.scc_findings.id
  description  = "Notify SCC findings to Pub/Sub"
}

data "archive_file" "function_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src/gcp_function_forwarder"
  output_path = "${path.module}/.tmp/gcp_function_forwarder.zip"
}

resource "google_cloudfunctions2_function" "forwarder" {
  name        = "${var.name_prefix}-mcspm-forwarder"
  location    = var.region
  build_config {
    runtime     = "python311"
    entry_point = "pubsub_entrypoint"
    source {
      storage_source {
        bucket = "placeholder-bucket" # consumer must provide CI/CD deploy, not local
        object = "gcp_function_forwarder.zip"
      }
    }
  }
  service_config {
    available_memory = "256M"
    timeout_seconds  = 60
    environment_variables = {
      SPLUNK_HEC_URL    = var.splunk_hec_url
      SPLUNK_HEC_TOKEN  = "from_gcp_secret_manager_at_runtime"
      SPLUNK_SOURCETYPE = "mcspm:finding"
      SPLUNK_SOURCE     = "gcp-scc"
      SPLUNK_INDEX      = var.splunk_index
    }
  }
  labels = var.labels
}
