package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trufflesecurity/logwarden/internal/result"
)

func TestWebhookHonorsCancellationWithoutLeakingCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (Slack{WebhookURL: "https://hooks.slack.com/services/synthetic-secret-never-send"}).Send(ctx, result.Result{})
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), "hooks.slack") {
		t.Fatal("unsafe or missing error", err)
	}
}

func TestWebhookDoesNotFollowRedirect(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	err := (Slack{WebhookURL: server.URL}).Send(context.Background(), result.Result{})
	if err == nil || followed {
		t.Fatal("redirected webhook could leak alert payload")
	}
}
