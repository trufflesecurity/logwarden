package main

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/storage"

	"github.com/alecthomas/kingpin/v2"

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

	policies     = app.Flag("policies", "Path to policies folder.").Default("policy").String()
	project      = app.Flag("project", "GCP Project ID.").String()
	subscription = app.Flag("subscription", "Pub/Sub subscription to audit.").String()
	secretName   = app.Flag("secret-name", "GCP Secret name to use for GCP Auditor.").Default("logwarden").String()

	// options
	jsonOut  = app.Flag("json", "Output results as JSON.").Bool()
	printAll = app.Flag("print-all", "Output all logs that are processed.").Bool()

	// outputs
	slackWebhookOut         = app.Flag("slack-webhook", "Enable Slack webhook.").Bool()
	webhookOut              = app.Flag("webhook", "Enable JSON HTTP POST webhook output.").Bool()
	notificationStateBucket = app.Flag("notification-state-bucket", "GCS bucket for durable Slack notification claims.").String()
	notificationPolicy      = app.Flag("notification-policy", "JSON notification policy path or gs:// object.").String()

	// runCmd is the default so that `logwarden --project=x --subscription=y` keeps working.
	runCmd = app.Command("run", "Audit a live Pub/Sub subscription and alert on violations.").Default()

	evalCmd    = app.Command("eval", "Replay saved log events against the policies. Prints to stdout only, never alerts.")
	evalEvents = evalCmd.Arg("events", "File of log events; omit to read stdin.").String()

	harvestCmd     = app.Command("harvest", "Capture log events off Pub/Sub into a file to replay with eval.")
	harvestLimit   = harvestCmd.Flag("limit", "Number of events to capture.").Default("500").Int()
	harvestTimeout = harvestCmd.Flag("timeout", "Give up waiting for events after this long.").Default("5m").Duration()
	harvestOutput  = harvestCmd.Arg("output", "File to write events to.").Default("testdata/events.ndjson").String()
)

func main() {
	cmd := kingpin.MustParse(app.Parse(os.Args[1:]))

	ctx := context.Background()

	switch cmd {
	case evalCmd.FullCommand():
		evaluate(ctx)
	case harvestCmd.FullCommand():
		harvest(ctx)
	case runCmd.FullCommand():
		serve(ctx)
	default:
		app.Fatalf("unknown command %q", cmd)
	}
}

// evaluate replays a file of log events against the policies. It deliberately ignores
// --slack-webhook and --webhook: the point of eval is that a half-baked rule cannot reach
// the alert channel, so there is no way to turn the alerting outputs back on.
func evaluate(ctx context.Context) {
	eng, err := engine.New(ctx, *policies, []outputs.Output{stdoutOutput()}, *printAll)
	if err != nil {
		log.Fatal(err)
	}

	in, err := openInput(*evalEvents)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = in.Close() }()

	events, byRule, err := eng.EvaluateStream(ctx, in)
	printTally(events, byRule)
	if err != nil {
		log.Fatal(err)
	}
}

// harvest captures live events to a file so they can be replayed with eval.
func harvest(ctx context.Context) {
	requireSubscription()

	// A quiet subscription would otherwise block forever waiting for --limit events, so
	// stop on a deadline or on Ctrl-C and keep whatever was captured.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *harvestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *harvestTimeout)
		defer cancel()
	}

	partial := *harvestOutput + ".partial"
	out, err := createOutput(partial)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, "Capturing up to %d events from %s (timeout %s, ctrl-c to stop early)...\n",
		*harvestLimit, *subscription, *harvestTimeout)

	captured, err := engine.Harvest(ctx, *project, *subscription, *harvestLimit, out)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		log.Fatalf("%v (captured %d events, kept at %s)", err, captured, partial)
	}

	if captured == 0 {
		_ = os.Remove(partial)
		log.Fatalf("captured no events from %s; %s left untouched", *subscription, *harvestOutput)
	}

	if err := os.Rename(partial, *harvestOutput); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, "Wrote %d events to %s\n", captured, *harvestOutput)
}

// serve is the original behaviour: audit a live subscription and alert on violations.
func serve(ctx context.Context) {
	requireSubscription()
	if !*slackWebhookOut && (*notificationStateBucket != "" || *notificationPolicy != "") {
		log.Fatal("notification suppression requires Slack output")
	}

	enabledOutputs := []outputs.Output{stdoutOutput()}

	// Only reach for Secret Manager when an output actually needs a credential from it.
	if *slackWebhookOut || *webhookOut {
		cfg, err := secret.GetSecret(ctx, *project, *secretName)
		if err != nil {
			log.Fatal(err)
		}

		if *slackWebhookOut {
			var output outputs.Output = slack.Slack{WebhookURL: cfg.MustGetField("SLACK_WEBHOOK")}
			if *notificationStateBucket != "" {
				if *notificationPolicy == "" {
					log.Fatal("notification-policy is required with durable notification state")
				}
				client, err := storage.NewClient(ctx)
				if err != nil {
					log.Fatal(err)
				}
				defer func() { _ = client.Close() }()
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

		if *webhookOut {
			enabledOutputs = append(enabledOutputs, webhook.Webhook{PostURL: cfg.MustGetField("WEBHOOK_URL")})
		}
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

func requireSubscription() {
	if *project == "" || *subscription == "" {
		app.Fatalf("--project and --subscription are required")
	}
}

func stdoutOutput() outputs.Output {
	if *jsonOut {
		return json.JSON{}
	}
	return human.Human{}
}

// printTally summarises a replay on stderr, leaving stdout clean for --json. The per-rule
// counts are the answer to "how much would this rule have posted to the alert channel?".
func printTally(events int, byRule map[string]int) {
	total := 0
	width := 0
	rules := make([]string, 0, len(byRule))
	for rule, n := range byRule {
		total += n
		rules = append(rules, rule)
		if len(rule) > width {
			width = len(rule)
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		if byRule[rules[i]] != byRule[rules[j]] {
			return byRule[rules[i]] > byRule[rules[j]]
		}
		return rules[i] < rules[j]
	})

	fmt.Fprintf(os.Stderr, "\n%d events, %d violations\n", events, total)
	for _, rule := range rules {
		fmt.Fprintf(os.Stderr, "  %-*s  %d\n", width, rule, byRule[rule])
	}
}

func openInput(path string) (io.ReadCloser, error) {
	if path == "" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(path)
}

func createOutput(path string) (*os.File, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return os.Create(path)
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
		defer func() { _ = reader.Close() }()
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
