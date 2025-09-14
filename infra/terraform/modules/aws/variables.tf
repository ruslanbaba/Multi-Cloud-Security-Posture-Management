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
variable "vpc_subnet_ids" { type = list(string), default = [] }
variable "vpc_security_group_ids" { type = list(string), default = [] }
variable "iam_boundary_policy_arn" { type = string, default = null }
variable "create_kms_key" { type = bool, default = false }
variable "tags" { type = map(string), default = {} }
