variable "environment" {
  description = "The environment in which the infrastructure will be deployed(dev, prod etc.)"
  type        = string
  default     = ""
}

variable "project_id" {
  description = "The ID of the Google Cloud project"
  type        = string
  default     = ""
}

variable "ingress" {
  description = "The ingress settings for the google cloud run function"
  type        = string
  default     = ""
}

variable "region" {
  description = "The region in which resources will be deployed"
  type        = string
  default     = ""
}

variable "organization_id" {
  description = "The ID of the Google Cloud organization"
  type        = string
  default     = ""
}

variable "logging_sink_filter" {
  description = "The filter to apply for the logging sink"
  type        = string
  default     = <<EOF
LOG_ID("cloudaudit.googleapis.com/activity") OR LOG_ID("externalaudit.googleapis.com/activity") OR LOG_ID("cloudaudit.googleapis.com/system_event") OR LOG_ID("externalaudit.googleapis.com/system_event") OR LOG_ID("cloudaudit.googleapis.com/access_transparency") OR LOG_ID("externalaudit.googleapis.com/access_transparency")
-protoPayload.serviceName="k8s.io"
EOF
}

variable "docker_image" {
  description = "The Docker image to use for the application"
  type        = string
  default     = ""
}

variable "env_secret_id" {
  description = "The ID of the Secret Manager secret for environment variables"
  type        = string
  default     = ""
}

variable "container_args" {
  description = "Arguments to pass to the logwarden container at startup"
  type        = list(string)
  default     = []
}

variable "policy_source_dir" {
  description = "Repo directory containing rego policy files"
  type        = string
  default     = ""
}

variable "config_values" {
  description = "Application configuration variables, stored in GSM."
  type        = string
  default     = ""
}
