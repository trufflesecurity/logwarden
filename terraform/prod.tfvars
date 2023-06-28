environment       = "prod"
project_id        = "thog-prod"
ingress           = "INGRESS_TRAFFIC_INTERNAL_ONLY"
region            = "us-central1"
organization_id   = "355714717819"
filter            = <<EOF
LOG_ID("cloudaudit.googleapis.com/activity") OR LOG_ID("externalaudit.googleapis.com/activity") OR LOG_ID("cloudaudit.googleapis.com/system_event") OR LOG_ID("externalaudit.googleapis.com/system_event") OR LOG_ID("cloudaudit.googleapis.com/access_transparency") OR LOG_ID("externalaudit.googleapis.com/access_transparency")
-protoPayload.serviceName="k8s.io"
EOF
docker_image      = "us-docker.pkg.dev/thog-artifacts/public/logwarden:latest"
container_args    = []
policy_source_dir = "../policy/gcp"
