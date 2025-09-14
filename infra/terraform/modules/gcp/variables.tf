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

# Zero Trust Network Variables
variable "enable_zero_trust_networking" { type = bool, default = false }
variable "enable_private_google_access" { type = bool, default = false }
variable "vpc_network" { type = string, default = null }
variable "allowed_egress_ranges" { type = list(string), default = ["0.0.0.0/0"] }
variable "enable_vpc_flow_logs" { type = bool, default = false }
variable "create_vpc_connector" { type = bool, default = false }
variable "vpc_connector_ip_range" { type = string, default = "10.8.0.0/28" }
