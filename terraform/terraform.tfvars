environment         = ""
project_id          = ""
ingress             = ""
region              = ""
organization_id     = ""
logging_sink_filter = <<EOF
LOG_ID("cloudaudit.googleapis.com/activity") OR LOG_ID("externalaudit.googleapis.com/activity") OR LOG_ID("cloudaudit.googleapis.com/system_event") OR LOG_ID("externalaudit.googleapis.com/system_event") OR LOG_ID("cloudaudit.googleapis.com/access_transparency") OR LOG_ID("externalaudit.googleapis.com/access_transparency")
-protoPayload.serviceName="k8s.io"
EOF
docker_image        = ""
container_args      = [""]
policy_source_dir   = ""
