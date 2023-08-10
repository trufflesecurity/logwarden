locals {
  project = "<google_project_id>"
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
