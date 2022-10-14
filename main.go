package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"

	"cloud.google.com/go/pubsub"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app          = kingpin.New("gcp-auditor", "GCP Auditor is a tool to audit GCP logs against a set of rego policies.")
	policies     = app.Flag("policies", "Path to policies folder.").Default("policy").String()
	project      = app.Flag("project", "GCP Project ID.").Required().String()
	subscription = app.Flag("subscription", "Pub/Sub subscription to audit.").Required().String()
	secretName   = app.Flag("secret-name", "GCP Secret name to use for GCP Auditor.").Default("gcp-auditor").String()
	slackWebhook = app.Flag("slack-webhook", "Enable Slack webhook.").Bool()

	webhookURL string
)

type engine struct {
	ruleset rego.PreparedEvalQuery
	results chan []result
}

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	ctx := context.TODO()

	secret, err := common.GetSecret(ctx, *project, *secretName)
	if err != nil {
		log.Fatal(err)
	}
	webhookURL = secret.MustGetField("SLACK_WEBHOOK")

	compiler, err := compiler(*policies)
	if err != nil {
		log.Fatal(err)
	}

	rules, err := rego.New(
		rego.Query("x = data"),
		rego.Compiler(compiler),
	).PrepareForEval(ctx)
	if err != nil {
		log.Fatal(err)
	}

	eng := engine{
		ruleset: rules,
		results: make(chan []result),
	}

	go eng.alert(ctx)

	err = eng.subscribe(ctx, *project, *subscription)
	if err != nil {
		log.Fatal(err)
	}
}

func (e engine) alert(ctx context.Context) {
	for res := range e.results {
		out, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(out))
		for _, r := range res {
			if *slackWebhook {
				err := sendSlackWebhook(ctx, r)
				if err != nil {
					log.Println(err)
				}
			}
		}
	}
}

// sendSlackWebhook will send a message to a Slack webhook.
func sendSlackWebhook(ctx context.Context, res result) error {
	type slackMessage struct {
		Text string `json:"text"`
	}

	var details string
	for k, v := range res.Details {
		if k == "link" {
			v = fmt.Sprintf("<%s|stackdriver>", v)
		}
		details += fmt.Sprintf("*%s*: %v\n", cases.Title(language.AmericanEnglish).String(k), v)
	}

	body, err := json.Marshal(slackMessage{
		Text: fmt.Sprintf(`*Rule*: %s
*Message*: %s
*Type*: %s
%s`, res.Rule, res.Message, res.Type, details),
	})
	if err != nil {
		return err
	}
	req, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	if req.StatusCode != 200 {
		return fmt.Errorf("status code %d", req.StatusCode)
	}
	return nil
}

// subscribe subscribes to a Pub/Sub subscription and evaluates each message against the ruleset.
func (e engine) subscribe(ctx context.Context, project, subscription string) error {
	client, err := pubsub.NewClient(ctx, project)
	if err != nil {
		return fmt.Errorf("pubsub.NewClient: %v", err)
	}
	defer client.Close()

	sub := client.Subscription(subscription)

	var received int32
	err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
		var data map[string]interface{}
		err = json.Unmarshal(msg.Data, &data)
		if err != nil {
			log.Fatal(err)
		}
		e.evaluate(ctx, data)
		atomic.AddInt32(&received, 1)
		msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("sub.Receive: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Received %d messages\n", received)
	return nil
}

func (e engine) evaluate(ctx context.Context, input map[string]interface{}) {
	results, err := e.ruleset.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
	}

	for _, res := range results {
		body, err := json.MarshalIndent(res.Bindings["x"], "", "  ")
		if err != nil {
			log.Fatal(err)
		}

		resRaw := resultRaw{}
		err = json.Unmarshal(body, &resRaw)
		if err != nil {
			log.Fatal(err)
		}

		results := []result{}

		for rule, checkData := range resRaw {
			for ruleType, violations := range checkData {
				if len(violations) > 0 {
					v := flattenViolationSlice(violations)

					results = append(results, result{
						Rule:    rule,
						Type:    ruleType,
						Message: v.Msg,
						Details: v.Details,
					})
				}
			}
		}

		if len(results) > 0 {
			e.results <- results
		}
	}
}

func flattenViolationSlice(v []violation) violation {
	var message string
	details := map[string]any{}

	for _, v := range v {
		message = v.Msg
		for k, v := range v.Details {
			details[k] = v
		}
	}

	return violation{
		Msg:     message,
		Details: details,
	}
}

// Instantiate the Open Policy Agent with a folder of .rego policies.
func compiler(directory string) (*ast.Compiler, error) {
	policies := map[string]string{}

	policyFilenames, err := globFiles(directory, ".rego")
	if err != nil {
		return nil, err
	}

	for _, fn := range policyFilenames {
		contents, err := ioutil.ReadFile(fn)
		if err != nil {
			return nil, err
		}
		policies[fn] = string(contents)
		log.Printf("Loaded policy %s", fn)
	}

	return ast.CompileModules(policies)
}

func globFiles(dir string, ext string) ([]string, error) {

	files := []string{}
	err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if filepath.Ext(path) == ext {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

type resultRaw map[string]map[string][]violation

type violation struct {
	Msg     string
	Details map[string]any
}

type result struct {
	Rule    string
	Type    string
	Message string
	Details map[string]any
}
