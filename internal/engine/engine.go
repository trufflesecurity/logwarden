package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"cloud.google.com/go/pubsub/v2"
	"cloud.google.com/go/storage"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/trufflesecurity/logwarden/internal/outputs"
	"github.com/trufflesecurity/logwarden/internal/result"
	"google.golang.org/api/iterator"
)

// maxEventBytes caps a single newline-delimited log event. Audit log entries routinely
// exceed bufio.Scanner's 64KiB default.
const maxEventBytes = 16 * 1024 * 1024

func New(ctx context.Context, policyPath string, outputs []outputs.Output, printAll bool) (*engine, error) {
	var compiler *ast.Compiler
	var err error
	// infer type of policy storage location based on path prefix
	switch {
	// GCS
	case strings.HasPrefix(policyPath, "gs://"):
		compiler, err = gcsCompiler(strings.TrimPrefix(policyPath, "gs://"))
		if err != nil {
			return nil, err
		}
	// Local file directory
	default:
		compiler, err = localCompiler(policyPath)
		if err != nil {
			return nil, err
		}
	}

	rules, err := rego.New(
		rego.Query("x = data"),
		rego.Compiler(compiler),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("rego.New: %w", err)
	}

	return &engine{
		ruleset:  rules,
		results:  make(chan []result.Result),
		outputs:  outputs,
		printAll: printAll,
	}, nil
}

type engine struct {
	ruleset  rego.PreparedEvalQuery
	results  chan []result.Result
	outputs  []outputs.Output
	printAll bool
}

func (e *engine) Alert(ctx context.Context) error {
	for res := range e.results {
		e.report(ctx, res)
	}

	return nil
}

// report fans a batch of violations out to every enabled output.
func (e *engine) report(ctx context.Context, res []result.Result) {
	for _, r := range res {
		for _, o := range e.outputs {
			err := o.Send(ctx, r)
			if err != nil {
				log.Println(err)
			}
		}
	}
}

// subscribe subscribes to a Pub/Sub subscription and evaluates each message against the ruleset.
func (e *engine) Subscribe(ctx context.Context, project, subscription string) error {
	client, err := pubsub.NewClient(ctx, project)
	if err != nil {
		return fmt.Errorf("pubsub.NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	sub := client.Subscriber(subscription)

	var received int32
	err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
		if e.printAll {
			fmt.Println(string(msg.Data))
		}

		var data map[string]interface{}
		if err := json.Unmarshal(msg.Data, &data); err != nil {
			// One malformed message must not take down the daemon.
			log.Printf("skipping message %s: %v", msg.ID, err)
			msg.Ack()
			return
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

// EvaluateStream replays log events from r against the ruleset, reporting violations to the
// configured outputs. It accepts newline-delimited JSON objects (what Pub/Sub delivers and
// what Harvest writes) or a single JSON array (what `gcloud logging read --format=json`
// emits). It returns the number of events seen and a per-rule violation count.
//
// ponytail: a JSON array is buffered whole; feed NDJSON for dumps too large to hold in memory.
func (e *engine) EvaluateStream(ctx context.Context, r io.Reader) (int, map[string]int, error) {
	events := 0
	byRule := map[string]int{}

	check := func(input map[string]interface{}) {
		events++
		results, err := e.Check(ctx, input)
		if err != nil {
			log.Printf("event %d: %v", events, err)
			return
		}
		for _, res := range results {
			byRule[res.Rule]++
		}
		e.report(ctx, results)
	}

	br := bufio.NewReaderSize(r, 64*1024)

	// Peek (without consuming) to tell an array apart from newline-delimited objects.
	head, err := br.Peek(64)
	if err != nil && !errors.Is(err, io.EOF) {
		return events, byRule, fmt.Errorf("read events: %w", err)
	}
	head = bytes.TrimLeft(head, " \t\r\n")

	if len(head) > 0 && head[0] == '[' {
		batch := []map[string]interface{}{}
		if err := json.NewDecoder(br).Decode(&batch); err != nil {
			return events, byRule, fmt.Errorf("decode event array: %w", err)
		}
		for _, input := range batch {
			check(input)
		}
		return events, byRule, nil
	}

	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64*1024), maxEventBytes)
	for line := 0; sc.Scan(); {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var input map[string]interface{}
		if err := json.Unmarshal(raw, &input); err != nil {
			// Skip the bad line rather than abandoning the rest of the dump.
			log.Printf("skipping malformed event on line %d: %v", line, err)
			continue
		}
		check(input)
	}
	if err := sc.Err(); err != nil {
		return events, byRule, fmt.Errorf("read events: %w", err)
	}

	return events, byRule, nil
}

// Harvest taps a Pub/Sub subscription and writes up to limit raw messages to w, one JSON
// object per line, for replaying with EvaluateStream. Every message is nacked so it is
// redelivered: this is a tap, not a consumer, and the live subscriber still gets everything
// captured here.
func Harvest(ctx context.Context, project, subscription string, limit int, w io.Writer) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("limit must be positive, got %d", limit)
	}

	client, err := pubsub.NewClient(ctx, project)
	if err != nil {
		return 0, fmt.Errorf("pubsub.NewClient: %w", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	seen := map[string]bool{}
	written := 0

	sub := client.Subscriber(subscription)
	// Everything here gets nacked and redelivered, so cap how much is in flight at once.
	// ponytail: on a subscription quieter than --limit this still spins until --timeout.
	sub.ReceiveSettings.MaxOutstandingMessages = limit

	err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
		// Hand it straight back to the subscription for the real consumer.
		defer msg.Nack()

		// One event per line, so a payload that arrives pretty-printed cannot split
		// itself across lines and break the replay.
		var line bytes.Buffer
		if err := json.Compact(&line, msg.Data); err != nil {
			log.Printf("skipping message %s: %v", msg.ID, err)
			return
		}
		line.WriteByte('\n')

		mu.Lock()
		defer mu.Unlock()

		// Nacked messages come right back to us; only count each one once.
		if written >= limit || seen[msg.ID] {
			return
		}
		seen[msg.ID] = true

		if _, err := w.Write(line.Bytes()); err != nil {
			log.Println(err)
			cancel()
			return
		}

		written++
		if written >= limit {
			cancel()
		}
	})
	// A cancelled or expired context is how this function stops; it is not a failure.
	if err != nil && ctx.Err() == nil {
		return written, fmt.Errorf("sub.Receive: %w", err)
	}

	return written, nil
}

func (e *engine) evaluate(ctx context.Context, input map[string]interface{}) {
	results, err := e.Check(ctx, input)
	if err != nil {
		log.Println(err)
		return
	}

	if len(results) > 0 {
		e.results <- results
	}
}

// Check evaluates a single log event against the ruleset and returns any violations.
func (e *engine) Check(ctx context.Context, input map[string]interface{}) ([]result.Result, error) {
	evaluated, err := e.ruleset.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("rego eval: %w", err)
	}

	results := []result.Result{}

	for _, res := range evaluated {
		body, err := json.Marshal(res.Bindings["x"])
		if err != nil {
			return nil, fmt.Errorf("marshal bindings: %w", err)
		}

		resRaw := resultRaw{}
		if err := json.Unmarshal(body, &resRaw); err != nil {
			return nil, fmt.Errorf("unmarshal bindings: %w", err)
		}

		for rule, checkData := range resRaw {
			for ruleType, violations := range checkData {
				if len(violations) > 0 {
					v := flattenViolationSlice(violations)

					results = append(results, result.Result{
						Rule:    rule,
						Type:    ruleType,
						Message: v.Msg,
						Details: v.Details,
					})
				}
			}
		}
	}

	return results, nil
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
func localCompiler(directory string) (*ast.Compiler, error) {
	policies := map[string]string{}

	policyFilenames, err := globFiles(directory, ".rego")
	if err != nil {
		return nil, err
	}

	for _, fn := range policyFilenames {
		contents, err := os.ReadFile(fn)
		if err != nil {
			return nil, err
		}
		policies[fn] = string(contents)
		log.Printf("Loaded policy %s", fn)
	}

	// An empty ruleset compiles fine and then silently matches nothing, which reads as
	// "no violations" instead of "wrong --policies path".
	if len(policies) == 0 {
		return nil, fmt.Errorf("no .rego policies found in %q", directory)
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

func gcsCompiler(directory string) (*ast.Compiler, error) {
	ctx := context.Background()
	policies := map[string]string{}

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	bucket := client.Bucket(directory)
	objects := bucket.Objects(ctx, nil)

	for {
		object, err := objects.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			log.Fatalf("Failed to list objects: %v", err)
		}

		objectName := object.Name

		// Skip if it's not a Rego file
		if !strings.HasSuffix(objectName, ".rego") {
			continue
		}

		// Get the GCS object (your Rego file)
		rc, err := bucket.Object(objectName).NewReader(ctx)
		if err != nil {
			log.Fatalf("Failed to read object: %v", err)
		}

		// Read the object data (Rego file content)
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			log.Fatalf("Failed to read data: %v", err)
		}

		policies[objectName] = string(data)
		log.Printf("Loaded policy %s", objectName)

	}

	log.Println("Loaded all policies")

	return ast.CompileModules(policies)
}

type resultRaw map[string]map[string][]violation

type violation struct {
	Msg     string
	Details map[string]any
}
