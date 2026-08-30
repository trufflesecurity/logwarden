package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/logwarden/internal/outputs"
	"github.com/trufflesecurity/logwarden/internal/result"
)

// evalOne compiles the shipped policies, evaluates a single log event against
// them, and returns the results. It fails the test rather than hanging if the
// event matches nothing, since evaluate only sends when there is a violation.
func evalOne(t *testing.T, event map[string]any) []result.Result {
	t.Helper()

	ctx := context.Background()

	e, err := New(ctx, "../../policy/gcp", nil, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got := make(chan []result.Result, 1)
	go func() {
		got <- <-e.results
	}()
	go func() { _ = e.evaluate(ctx, event) }()

	select {
	case results := <-got:
		return results
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for a violation; the policies compiled but nothing matched")
		return nil
	}
}

// The shipped policies were rewritten from Rego v0 to the `contains ... if`
// form when OPA moved to v1.x, and the engine now compiles them with the v1
// parser. That is a silent change: a policy that no longer matches produces no
// alert rather than an error. This walks the real compile-and-evaluate path to
// pin the behaviour down -- the policies still compile, a matching log event
// still produces a violation, and the violation still unmarshals into the
// result shape the outputs consume.
func TestEvaluateSetRule(t *testing.T) {
	// A service account key creation, the event service_account_keys.rego
	// matches. It carries no authorizationInfo, so the mitre policies -- which
	// all key off that field -- stay quiet and this asserts a single result.
	results := evalOne(t, map[string]any{
		"protoPayload": map[string]any{
			"methodName": "google.iam.admin.v1.CreateServiceAccountKey",
			"authenticationInfo": map[string]any{
				"principalEmail": "attacker@example.com",
			},
		},
		"resource": map[string]any{
			"labels": map[string]any{
				"email_id": "svc@example.iam.gserviceaccount.com",
			},
		},
	})

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}

	r := results[0]
	if r.Rule != "service_account_keys" {
		t.Errorf("Rule = %q, want %q", r.Rule, "service_account_keys")
	}
	if r.Type != "violation" {
		t.Errorf("Type = %q, want %q", r.Type, "violation")
	}
	if r.Message != "service account key created" {
		t.Errorf("Message = %q, want %q", r.Message, "service account key created")
	}
	if got, want := r.Details["actor"], "attacker@example.com"; got != want {
		t.Errorf("Details[actor] = %v, want %v", got, want)
	}
	if got, want := r.Details["service_account"], "svc@example.iam.gserviceaccount.com"; got != want {
		t.Errorf("Details[service_account] = %v, want %v", got, want)
	}
}

// The mitre policies match through the shared mitre_helpers functions, so this
// exercises cross-package function calls resolving under the v1 parser and the
// functions-only helper package staying invisible to the engine's `data`
// query. A break in either would silently stop these rules from matching.
func TestEvaluateMitreHelpersRule(t *testing.T) {
	// A bucket listing, which mitre_discovery matches via
	// mitre_helpers.match.
	results := evalOne(t, map[string]any{
		"insertId":  "abc123",
		"timestamp": "2026-01-01T00:00:00Z",
		"protoPayload": map[string]any{
			"methodName": "storage.buckets.list",
			"authenticationInfo": map[string]any{
				"principalEmail": "attacker@example.com",
			},
			"authorizationInfo": []any{
				map[string]any{
					"permission": "storage.buckets.list",
					"granted":    true,
					"resource":   "projects/_/buckets/x",
				},
			},
		},
		"resource": map[string]any{
			"labels": map[string]any{"project_id": "my-project"},
		},
	})

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}

	r := results[0]
	if r.Rule != "mitre_discovery" {
		t.Errorf("Rule = %q, want %q", r.Rule, "mitre_discovery")
	}
	if r.Message != "possible discovery attempt" {
		t.Errorf("Message = %q, want %q", r.Message, "possible discovery attempt")
	}
	if got, want := r.Details["permission"], "storage.buckets.list"; got != want {
		t.Errorf("Details[permission] = %v, want %v", got, want)
	}
	if got, want := r.Details["granted"], true; got != want {
		t.Errorf("Details[granted] = %v, want %v", got, want)
	}
}

type capture struct{ got []result.Result }

func (c *capture) Send(_ context.Context, res result.Result) error {
	c.got = append(c.got, res)
	return nil
}

func newTestEngine(t *testing.T) (*engine, *capture) {
	t.Helper()

	got := &capture{}
	eng, err := New(context.Background(), filepath.Join("testdata", "policy"), []outputs.Output{got}, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return eng, got
}

// The probe policy fires on exactly one of the two fixture events, in both input shapes.
func TestEvaluateStream(t *testing.T) {
	for _, name := range []string{"events.ndjson", "events.json"} {
		name := name
		t.Run(name, func(t *testing.T) {
			eng, got := newTestEngine(t)

			raw, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}

			events, byRule, err := eng.EvaluateStream(context.Background(), bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("EvaluateStream: %v", err)
			}

			if events != 2 {
				t.Errorf("events = %d, want 2", events)
			}
			if byRule["probe"] != 1 {
				t.Errorf("byRule = %v, want probe:1", byRule)
			}
			if len(got.got) != 1 {
				t.Fatalf("sent %d results, want 1: %v", len(got.got), got.got)
			}

			res := got.got[0]
			if res.Rule != "probe" || res.Type != "violation" || res.Message != "probe fired" {
				t.Errorf("got %+v", res)
			}
			if res.Details["actor"] != "alice@example.com" {
				t.Errorf("actor = %v, want alice@example.com", res.Details["actor"])
			}
		})
	}
}

// A corrupt line in a dump must not abandon the events after it.
func TestEvaluateStreamSkipsMalformedLines(t *testing.T) {
	eng, got := newTestEngine(t)

	in := strings.Join([]string{
		`{"protoPayload":{"methodName":"test.probe.Fire","authenticationInfo":{"principalEmail":"alice@example.com"}}}`,
		`{"protoPayload":{"methodName":`,
		``,
		`{"protoPayload":{"methodName":"test.probe.Fire","authenticationInfo":{"principalEmail":"carol@example.com"}}}`,
	}, "\n")

	events, byRule, err := eng.EvaluateStream(context.Background(), strings.NewReader(in))
	if err != nil {
		t.Fatalf("EvaluateStream: %v", err)
	}

	if events != 2 {
		t.Errorf("events = %d, want 2 (the malformed and blank lines skipped)", events)
	}
	if byRule["probe"] != 2 || len(got.got) != 2 {
		t.Errorf("byRule = %v, sent %d results, want 2 of each", byRule, len(got.got))
	}
}

// An empty or wrong --policies path must fail loudly instead of matching nothing.
func TestNewRejectsEmptyPolicyDir(t *testing.T) {
	if _, err := New(context.Background(), t.TempDir(), nil, false); err == nil {
		t.Fatal("expected an error for a directory with no .rego files")
	}
}

// A UTF-8 BOM used to be read as the first event's opening byte, which dropped event one
// from an NDJSON dump and made a JSON array parse as zero events with no error at all.
func TestEvaluateStreamSkipsBOM(t *testing.T) {
	for _, name := range []string{"events.ndjson", "events.json"} {
		t.Run(name, func(t *testing.T) {
			eng, got := newTestEngine(t)

			raw, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}

			events, _, err := eng.EvaluateStream(context.Background(),
				bytes.NewReader(append([]byte("\xef\xbb\xbf"), raw...)))
			if err != nil {
				t.Fatalf("EvaluateStream: %v", err)
			}
			if events != 2 || len(got.got) != 1 {
				t.Errorf("events = %d, results = %d; want 2 and 1", events, len(got.got))
			}
		})
	}
}

// Input that parses to nothing is a format mistake. Reporting it as a clean zero-violation
// run would read as "this rule is quiet" to anyone using eval as a gate.
func TestEvaluateStreamRejectsUnparseableInput(t *testing.T) {
	eng, _ := newTestEngine(t)

	if _, _, err := eng.EvaluateStream(context.Background(), strings.NewReader("not json\n")); err == nil {
		t.Fatal("expected an error when no events could be parsed")
	}

	// An genuinely empty stream is not an error.
	if _, _, err := eng.EvaluateStream(context.Background(), strings.NewReader("  \n")); err != nil {
		t.Fatalf("empty input: %v", err)
	}
}
