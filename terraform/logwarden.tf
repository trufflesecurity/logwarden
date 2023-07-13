resource "google_secret_manager_secret" "config" {
  secret_id = "logwarden"
  labels = {
    secretmanager = "logwarden"
  }
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "config" {
  secret = google_secret_manager_secret.config.id
  # this is populated from Spacelift
  secret_data = var.config_values
}

module "logwarden" {
  source  = "spacelift.io/trufflesec/logwarden/gcp"
  version = "0.1.4"

  # These are defined in per-env tfvars files(see prod.tfvars)
  # expansion to multiple regions/envs will have some variables injected from CI or Spacelift
  environment         = var.environment
  project_id          = var.project_id
  ingress             = var.ingress
  region              = var.region
  organization_id     = var.organization_id
  logging_sink_filter = var.logging_sink_filter
  docker_image        = var.docker_image
  config_secret_id    = google_secret_manager_secret.config.secret_id
  container_args      = var.container_args
  policy_source_dir   = var.policy_source_dir

  #ensure that the secret value is available before attempting to deploy infra
  depends_on = [google_secret_manager_secret_version.config]
}
