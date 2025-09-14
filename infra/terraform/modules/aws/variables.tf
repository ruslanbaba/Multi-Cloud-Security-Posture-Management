variable "name_prefix" { type = string }
variable "region" { type = string }
variable "splunk_hec_url" { type = string }
variable "splunk_hec_token_secret_arn" { type = string }
variable "splunk_index" { type = string, default = null }
variable "enable_security_hub" { type = bool, default = true }
variable "lambda_timeout" { type = number, default = 30 }
variable "lambda_memory_mb" { type = number, default = 256 }
variable "lambda_reserved_concurrency" { type = number, default = null }
variable "lambda_kms_key_arn" { type = string, default = null }
variable "lambda_kms_key_arn" { type = string, default = null }
variable "tags" { type = map(string), default = {} }
