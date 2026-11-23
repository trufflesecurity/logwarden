# Durable Slack notification suppression

Enable the optional Slack gate with both flags:

```
--slack-webhook
--notification-state-bucket=YOUR_STATE_BUCKET
--notification-policy=gs://YOUR_POLICY_BUCKET/notification-policy.json
```

The policy may also be a local JSON file. It is loaded and validated at startup;
use a new object name and restart the service when changing it. Give the runtime
identity read access to the policy object and `roles/storage.objectUser` on a
dedicated state bucket. Keep that bucket private. A seven-day deletion lifecycle
bounds storage; it exceeds the maximum supported one-day repeat window.

```json
{
  "repeat_window_seconds": 3600,
  "exceptions": [
    {
      "id": "temporary-maintenance",
      "starts_at": "2026-09-13T18:20:56Z",
      "expires_at": "2026-09-20T18:20:56Z",
      "match": {
        "Rule": "cloud_sql_connect",
        "Type": "violation",
        "Message": "unexpected connection to cloudsql instance",
        "Details": {
          "instance": "example:maintenance",
          "project": "example",
          "actor": "maintenance@example.iam.gserviceaccount.com"
        }
      }
    }
  ]
}
```

An exception requires all six exact match fields above and lasts at most seven
days. Its UTC processing-time interval includes the start and excludes the end;
event timestamps cannot extend it. Ignored alerts never access or extend claims,
so the exception itself leaves no cooldown after expiry. Malformed policies fail
startup. The default repeat window is one hour, with a supported range of 1–86400
seconds.

Repeat identity includes rule, type, message, and every detail except top-level
`link`, `insertId`, and `timestamp`. SHA-256 object names reveal no raw identity;
objects contain only status and expiration times. GCS generation preconditions
make claims exclusive across instances and restarts. Repeats do not extend the
window. An active one-minute reservation prevents overlapping delivery even with
a short repeat window; storage and delivery together are bounded to 45 seconds.

JSON/human detector output remains unchanged and precedes the Slack gate. Raw
Cloud Audit logs remain in Logging. Structured `logwarden_notifications` records
report `time_ignored`, `repeat_suppressed`, `delivered`, `delivery_uncertain`, or
`delivery_commit_failed` with only a fingerprint and expiry. Notification
failures propagate through the engine, and Pub/Sub acknowledges only after all
outputs complete. Storage claim errors send nothing and cause a NACK.

Slack webhooks do not accept an idempotency key. If a request fails ambiguously or
the process dies after reserving, the claim is retained as uncertain for the
remainder of the repeat window. The first observed send failure causes a NACK;
a retry encountering a durable uncertain claim is suppressed and acknowledged.
This prevents a retry flood but can miss a Slack notification in that window.
The audit records remain available; this is not an exactly-once delivery promise.
Deleting active claim objects can resend notifications and should be avoided.

Run `go test -race ./...` for policy boundaries, scope, concurrent delivery,
restarts, uncertain outcomes, storage failures, native SDK preconditions, and the
engine acknowledgment boundary. Set `LOGWARDEN_TEST_POLICY=/path/to/config.json`
to validate an actual deployment file. The opt-in live storage check uses a unique
synthetic claim, four competing replicas, and a fresh client, with no Slack calls:

```
LOGWARDEN_TEST_STATE_BUCKET=YOUR_STATE_BUCKET \
  go test -race -v ./internal/outputs/notify -run TestLiveGCSReplicasRestartAndCAS
```

It uses Application Default Credentials, or `GOOGLE_OAUTH_ACCESS_TOKEN` when
provided, and leaves one small synthetic status object for lifecycle deletion.
