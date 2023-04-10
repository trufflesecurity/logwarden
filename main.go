package main

import (
	"context"
	"log"
	"os"

	"github.com/trufflesecurity/gcp-auditor/internal/engine"
	"github.com/trufflesecurity/gcp-auditor/internal/outputs"
	"github.com/trufflesecurity/gcp-auditor/internal/outputs/human"
	"github.com/trufflesecurity/gcp-auditor/internal/outputs/json"
	"github.com/trufflesecurity/gcp-auditor/internal/outputs/slack"
	"github.com/trufflesecurity/gcp-auditor/internal/outputs/webhook"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app = kingpin.New("gcp-auditor", "GCP Auditor is a tool to audit GCP logs against a set of rego policies.")

	// required
	policies     = app.Flag("policies", "Path to policies folder.").Default("policy").String()
	project      = app.Flag("project", "GCP Project ID.").Required().String()
	subscription = app.Flag("subscription", "Pub/Sub subscription to audit.").Required().String()
	secretName   = app.Flag("secret-name", "GCP Secret name to use for GCP Auditor.").Default("gcp-auditor").String()

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

	err = eng.Subscribe(ctx, *project, *subscription)
	if err != nil {
		log.Fatal(err)
	}
}
