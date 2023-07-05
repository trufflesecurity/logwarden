locals {
  terraform_service_account = ""
  project                   = ""
}

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.61.0"
    }
  }
}


provider "google" {
  project         = local.project
  request_timeout = "60s"
  region          = var.region
}
