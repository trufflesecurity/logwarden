
resource "google_logging_organization_sink" "audit-logs" {
  name   = "audit-logs"
  description = "audit logs for the organization"
  org_id = var.organization_id

  destination = "pubsub.googleapis.com/${google_pubsub_topic.audit-logs.id}"

  include_children = true

  filter = var.logging_sink_filter
}

data "google_iam_policy" "sink_topic_iam_policy_data" {
  binding {
    members = [google_logging_organization_sink.audit-logs.writer_identity]
    role = "roles/pubsub.publisher"
  }
}

resource "google_pubsub_topic_iam_policy" "sink_topic_iam_poicy" {
  project     = var.project_id
  policy_data = data.google_iam_policy.sink_topic_iam_policy_data.policy_data
  topic       = google_pubsub_topic.audit-logs.name
}

resource "google_pubsub_topic" "audit-logs" {
  name = "audit-logs"
  project = var.project_id
}

resource "google_pubsub_subscription" "gcp-auditor" {
  name  = "gcp-auditor"
  topic = google_pubsub_topic.audit-logs.name
  project = var.project_id

  message_retention_duration = "3600s"
  retain_acked_messages      = true

  ack_deadline_seconds = 20

  expiration_policy {
    ttl = "432000s" // 5 days, but 24h is the minimum
  }
  retry_policy {
    minimum_backoff = "10s"
  }

  enable_message_ordering    = false
}

resource "google_pubsub_subscription" "gcp-auditor-test" {
  name  = "gcp-auditor-test"
  topic = google_pubsub_topic.audit-logs.name
  project = var.project_id

  message_retention_duration = "3600s"
  retain_acked_messages      = true

  ack_deadline_seconds = 20

  expiration_policy {
    ttl = "86400s" // 24h is the minimum
  }
  retry_policy {
    minimum_backoff = "10s"
  }

  enable_message_ordering    = false
}
