package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/trufflesecurity/logwarden/internal/engine"
	"github.com/trufflesecurity/logwarden/internal/outputs"
	"github.com/trufflesecurity/logwarden/internal/outputs/human"
	"github.com/trufflesecurity/logwarden/internal/outputs/json"
	"github.com/trufflesecurity/logwarden/internal/outputs/slack"
	"github.com/trufflesecurity/logwarden/internal/outputs/webhook"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("logwarden", "Logwarden is a tool to audit GCP logs against a set of rego policies.")

	// required
	policyBucket = app.Flag("policy-bucket", "GCS bucket containing policies.").Default("").String()
	policies     = app.Flag("policies", "Path to policies folder.").Default("").String()
	project      = app.Flag("project", "GCP Project ID.").Required().String()
	subscription = app.Flag("subscription", "Pub/Sub subscription to audit.").Required().String()
	secretName   = app.Flag("secret-name", "GCP Secret name to use for GCP Auditor.").Default("logwarden").String()

	// options
	jsonOut = app.Flag("json", "Output results as JSON.").Bool()

	// outputs
	slackWebhookOut = app.Flag("slack-webhook", "Enable Slack webhook.").Bool()
	webhookOut      = app.Flag("webhook", "Enable JSON HTTP POST webhook output.").Bool()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	ctx := context.TODO()

	secret, err := common.GetSecret(ctx, *project, *secretName)
	if err != nil {
		log.Fatal(err)
	}

	enabledOutputs := []outputs.Output{}

	if *policyBucket == "" && *policies == "" {
		log.Fatal("You must specify either a local file directory or GCS bucket.")
	}

	if *jsonOut {
		enabledOutputs = append(enabledOutputs, json.JSON{})
	} else {
		enabledOutputs = append(enabledOutputs, human.Human{})
	}

	if *slackWebhookOut {
		slackWebhookURL := secret.MustGetField("SLACK_WEBHOOK")
		enabledOutputs = append(enabledOutputs, slack.Slack{WebhookURL: slackWebhookURL})
	}

	if *webhookOut {
		webhookURL := secret.MustGetField("WEBHOOK_URL")
		enabledOutputs = append(enabledOutputs, webhook.Webhook{PostURL: webhookURL})
	}

	eng, err := engine.New(ctx, *policies, enabledOutputs)
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
