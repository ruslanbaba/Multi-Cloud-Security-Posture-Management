variable "project_id" { type = string }
variable "region" { type = string }
variable "name_prefix" { type = string }
variable "splunk_hec_url" { type = string }
variable "splunk_hec_token_secret" { type = string } # Secret Manager secret id
variable "splunk_index" { type = string, default = null }
variable "enable_notification" { type = bool, default = true }
variable "organization_id" { type = string, default = null }
variable "vpc_connector_name" { type = string, default = null }
variable "max_instance_count" { type = number, default = 10 }
variable "iam_boundary_policy" { type = string, default = null }
variable "labels" { type = map(string), default = {} }
