variable "project_id" { type = string }
variable "region" { type = string }
variable "name_prefix" { type = string }
variable "splunk_hec_url" { type = string }
variable "splunk_hec_token_secret" { type = string } # Secret Manager secret id
variable "splunk_index" { type = string, default = null }
variable "enable_notification" { type = bool, default = true }
variable "labels" { type = map(string), default = {} }
