package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/trufflesecurity/logwarden/internal/outputs"
	"github.com/trufflesecurity/logwarden/internal/result"
)

type outputFunc func(context.Context, result.Result) error

func (send outputFunc) Send(ctx context.Context, res result.Result) error { return send(ctx, res) }

func testEngine(t *testing.T, policy string, out ...outputs.Output) *engine {
	t.Helper()
	rules, err := rego.New(rego.Query("x = data"), rego.Module("test.rego", policy)).PrepareForEval(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &engine{ruleset: rules, results: make(chan deliveryBatch), outputs: out}
}

const testPolicy = `package test
violation[{"msg":"test violation","details":{"actor":"test actor"}}] { input.alert == true }`

func receiveError(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("operation remained blocked")
		return nil
	}
}

func TestEvaluateWaitsForDeliveryAndPropagatesFailure(t *testing.T) {
	for _, failure := range []error{nil, errors.New("storage or output unavailable")} {
		t.Run(stringResult(failure), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			var audited bool
			eng := testEngine(t, testPolicy,
				outputFunc(func(ctx context.Context, res result.Result) error {
					if res.Rule != "test" || res.Type != "violation" || res.Message != "test violation" || res.Details["actor"] != "test actor" {
						t.Error("evaluated result changed", res)
					}
					close(entered)
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-release:
						return failure
					}
				}),
				outputFunc(func(context.Context, result.Result) error { audited = true; return nil }),
			)
			alertDone, evaluationDone := make(chan error, 1), make(chan error, 1)
			go func() { alertDone <- eng.Alert(ctx) }()
			go func() { evaluationDone <- eng.evaluate(ctx, map[string]interface{}{"alert": true}) }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("output was not called")
			}
			select {
			case err := <-evaluationDone:
				t.Fatal("evaluation acknowledged unfinished delivery", err)
			default:
			}
			close(release)
			if err := receiveError(t, evaluationDone); !errors.Is(err, failure) {
				t.Fatalf("delivery error = %v, want %v", err, failure)
			}
			if !audited {
				t.Fatal("failed notification prevented audit output")
			}
			cancel()
			if err := receiveError(t, alertDone); !errors.Is(err, context.Canceled) {
				t.Fatal("alert loop did not stop on cancellation", err)
			}
		})
	}
}

func stringResult(err error) string {
	if err != nil {
		return "failure"
	}
	return "success"
}

func TestEvaluateCancellationAndMalformedPolicyReturnErrors(t *testing.T) {
	eng := testEngine(t, testPolicy)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- eng.evaluate(ctx, map[string]interface{}{"alert": true}) }()
	cancel()
	if err := receiveError(t, done); err == nil {
		t.Fatal("canceled evaluation succeeded without an alert consumer")
	}
	// Once queued, cancellation also releases evaluate while an output is pending.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- eng.evaluate(ctx, map[string]interface{}{"alert": true}) }()
	var batch deliveryBatch
	select {
	case batch = <-eng.results:
	case <-time.After(2 * time.Second):
		t.Fatal("evaluation did not queue delivery")
	}
	cancel()
	if err := receiveError(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal("pending delivery did not return cancellation", err)
	}
	select {
	case batch.done <- nil:
	default:
		t.Fatal("late delivery completion would block alert loop")
	}
	if err := eng.evaluate(context.Background(), map[string]interface{}{"alert": false}); err != nil {
		t.Fatal("non-violation required delivery", err)
	}
	malformed := testEngine(t, "package test\nviolation := 123")
	if err := malformed.evaluate(context.Background(), map[string]interface{}{}); err == nil {
		t.Fatal("malformed policy result did not return an error")
	}
}

func TestProductionPoliciesCompile(t *testing.T) {
	policyDir := os.Getenv("LOGWARDEN_POLICY_TEST_DIR")
	if policyDir == "" {
		t.Skip("set LOGWARDEN_POLICY_TEST_DIR to a production policy snapshot")
	}
	if _, err := os.Stat(filepath.Join(policyDir, "cloud-sql-connect.rego")); err != nil {
		t.Fatal(err)
	}
	eng, err := New(context.Background(), policyDir, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.evaluate(context.Background(), map[string]interface{}{}); err != nil {
		t.Fatal(err)
	}
}
