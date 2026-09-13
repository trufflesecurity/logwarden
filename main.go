package main

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/trufflesecurity/logwarden/internal/engine"
	"github.com/trufflesecurity/logwarden/internal/outputs"
	"github.com/trufflesecurity/logwarden/internal/outputs/human"
	"github.com/trufflesecurity/logwarden/internal/outputs/json"
	"github.com/trufflesecurity/logwarden/internal/outputs/notify"
	"github.com/trufflesecurity/logwarden/internal/outputs/slack"
	"github.com/trufflesecurity/logwarden/internal/outputs/webhook"
	"github.com/trufflesecurity/logwarden/internal/secret"
)

var (
	app = kingpin.New("logwarden", "Logwarden is a tool to audit GCP logs against a set of rego policies.")

	// required
	policies     = app.Flag("policies", "Path to policies folder.").Default("policies").String()
	project      = app.Flag("project", "GCP Project ID.").Required().String()
	subscription = app.Flag("subscription", "Pub/Sub subscription to audit.").Required().String()
	secretName   = app.Flag("secret-name", "GCP Secret name to use for GCP Auditor.").Default("logwarden").String()

	// options
	jsonOut  = app.Flag("json", "Output results as JSON.").Bool()
	printAll = app.Flag("print-all", "Output all logs that are processed.").Bool()

	// outputs
	slackWebhookOut         = app.Flag("slack-webhook", "Enable Slack webhook.").Bool()
	webhookOut              = app.Flag("webhook", "Enable JSON HTTP POST webhook output.").Bool()
	notificationStateBucket = app.Flag("notification-state-bucket", "GCS bucket for durable Slack notification claims.").String()
	notificationPolicy      = app.Flag("notification-policy", "JSON notification policy path or gs:// object.").String()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	ctx := context.TODO()

	secret, err := secret.GetSecret(ctx, *project, *secretName)
	if err != nil {
		log.Fatal(err)
	}

	enabledOutputs := []outputs.Output{}

	if *jsonOut {
		enabledOutputs = append(enabledOutputs, json.JSON{})
	} else {
		enabledOutputs = append(enabledOutputs, human.Human{})
	}

	if *slackWebhookOut {
		slackWebhookURL := secret.MustGetField("SLACK_WEBHOOK")
		var output outputs.Output = slack.Slack{WebhookURL: slackWebhookURL}
		if *notificationStateBucket != "" {
			if *notificationPolicy == "" {
				log.Fatal("notification-policy is required with durable notification state")
			}
			client, err := storage.NewClient(ctx)
			if err != nil {
				log.Fatal(err)
			}
			defer client.Close()
			policy, err := loadNotificationPolicy(ctx, client, *notificationPolicy)
			if err != nil {
				log.Fatal(err)
			}
			output = notify.Output{Store: notify.GCS{Bucket: client.Bucket(*notificationStateBucket)}, Config: policy, Next: output,
				Audit: func(event, fingerprint string, until time.Time) {
					_ = stdjson.NewEncoder(os.Stdout).Encode(map[string]any{"component": "logwarden_notifications", "event": event, "fingerprint": fingerprint, "until": until.UTC()})
				}}
		} else if *notificationPolicy != "" {
			log.Fatal("notification-state-bucket is required with notification-policy")
		}
		enabledOutputs = append(enabledOutputs, output)
	}
	if !*slackWebhookOut && (*notificationStateBucket != "" || *notificationPolicy != "") {
		log.Fatal("notification suppression requires Slack output")
	}

	if *webhookOut {
		webhookURL := secret.MustGetField("WEBHOOK_URL")
		enabledOutputs = append(enabledOutputs, webhook.Webhook{PostURL: webhookURL})
	}

	eng, err := engine.New(ctx, *policies, enabledOutputs, *printAll)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		err := eng.Alert(ctx)
		if err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		log.Fatal(http.ListenAndServe(":"+port, nil))
	}()

	err = eng.Subscribe(ctx, *project, *subscription)
	if err != nil {
		log.Fatal(err)
	}
}

func loadNotificationPolicy(ctx context.Context, client *storage.Client, path string) (notify.Config, error) {
	var body []byte
	var err error
	if strings.HasPrefix(path, "gs://") {
		parts := strings.SplitN(strings.TrimPrefix(path, "gs://"), "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return notify.Config{}, fmt.Errorf("invalid notification policy object")
		}
		reader, openErr := client.Bucket(parts[0]).Object(parts[1]).NewReader(ctx)
		if openErr != nil {
			return notify.Config{}, openErr
		}
		defer reader.Close()
		body, err = io.ReadAll(io.LimitReader(reader, 65537))
	} else {
		body, err = os.ReadFile(path)
	}
	if err != nil {
		return notify.Config{}, err
	}
	if len(body) > 65536 {
		return notify.Config{}, fmt.Errorf("notification policy too large")
	}
	return notify.ParseConfig(body)
}
