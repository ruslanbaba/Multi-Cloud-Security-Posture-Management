terraform {
  required_version = ">= 1.5.0"
}

provider "aws" {
  region = var.aws_region
}

module "aws_mcspm" {
  source                         = "../../modules/aws"
  name_prefix                    = "prod"
  region                         = var.aws_region
  splunk_hec_url                 = var.splunk_hec_url
  splunk_hec_token_secret_arn    = var.splunk_hec_token_secret_arn
  splunk_index                   = var.splunk_index
  tags                           = { env = "prod" }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

module "gcp_mcspm" {
  source                    = "../../modules/gcp"
  name_prefix               = "prod"
  project_id                = var.gcp_project
  region                    = var.gcp_region
  splunk_hec_url            = var.splunk_hec_url
  splunk_hec_token_secret   = var.gcp_splunk_hec_token_secret
  splunk_index              = var.splunk_index
  labels                    = { env = "prod" }
}
