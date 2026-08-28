package engine

import (
	"context"
	"testing"
	"time"

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
	go e.evaluate(ctx, event)

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
