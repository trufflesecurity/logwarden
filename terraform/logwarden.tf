resource "google_secret_manager_secret" "config" {
  secret_id = var.env_secret_id
  labels = {
    secretmanager = var.env_secret_id
  }
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "config" {
  secret = google_secret_manager_secret.config.id
  # this can be populated from platform tools like Spacelift, or CI.
  secret_data = var.config_values
}

module "logwarden" {
  source = "github.com/trufflesecurity/terraform-gcp-logwarden?ref=1.0.0"

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
