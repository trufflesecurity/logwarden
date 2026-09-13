package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/trufflesecurity/logwarden/internal/outputs"
	"github.com/trufflesecurity/logwarden/internal/result"
	"google.golang.org/api/iterator"
)

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
		results:  make(chan deliveryBatch),
		outputs:  outputs,
		printAll: printAll,
	}, nil
}

type engine struct {
	ruleset  rego.PreparedEvalQuery
	results  chan deliveryBatch
	outputs  []outputs.Output
	printAll bool
}

type deliveryBatch struct {
	ctx     context.Context
	results []result.Result
	done    chan error
}

func (e *engine) Alert(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch, ok := <-e.results:
			if !ok {
				return nil
			}
			var deliveryErr error
			for _, r := range batch.results {
				for _, o := range e.outputs {
					if err := o.Send(batch.ctx, r); err != nil && deliveryErr == nil {
						deliveryErr = fmt.Errorf("output delivery: %w", err)
					}
				}
			}
			batch.done <- deliveryErr
		}
	}
}

// subscribe subscribes to a Pub/Sub subscription and evaluates each message against the ruleset.
func (e *engine) Subscribe(ctx context.Context, project, subscription string) error {
	client, err := pubsub.NewClient(ctx, project)
	if err != nil {
		return fmt.Errorf("pubsub.NewClient: %v", err)
	}
	defer client.Close()

	sub := client.Subscription(subscription)

	var received int32
	err = sub.Receive(ctx, func(messageCtx context.Context, msg *pubsub.Message) {
		if e.printAll {
			fmt.Println(string(msg.Data))
		}

		var data map[string]interface{}
		if err := json.Unmarshal(msg.Data, &data); err != nil || data == nil {
			log.Println("Invalid Pub/Sub JSON object; retaining message for retry")
			msg.Nack()
			return
		}
		if err := e.evaluate(messageCtx, data); err != nil {
			log.Printf("Evaluation or delivery failed; retaining message for retry: %v", err)
			msg.Nack()
			return
		}
		atomic.AddInt32(&received, 1)
		msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("sub.Receive: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Received %d messages\n", received)
	return nil
}

func (e *engine) evaluate(ctx context.Context, input map[string]interface{}) error {
	results, err := e.ruleset.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return fmt.Errorf("evaluate policy: %w", err)
	}

	for _, res := range results {
		body, err := json.MarshalIndent(res.Bindings["x"], "", "  ")
		if err != nil {
			return fmt.Errorf("encode policy results: %w", err)
		}

		resRaw := resultRaw{}
		err = json.Unmarshal(body, &resRaw)
		if err != nil {
			return fmt.Errorf("decode policy results: %w", err)
		}

		results := []result.Result{}

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

		if len(results) > 0 {
			batch := deliveryBatch{ctx: ctx, results: results, done: make(chan error, 1)}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case e.results <- batch:
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-batch.done:
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
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
		rc.Close()
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
