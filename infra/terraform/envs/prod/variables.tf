variable "aws_region" { type = string }
variable "gcp_project" { type = string }
variable "gcp_region" { type = string }
variable "splunk_hec_url" { type = string }
variable "splunk_hec_token_secret_arn" { type = string }
variable "gcp_splunk_hec_token_secret" { type = string }
variable "splunk_index" { type = string, default = null }
