package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/trufflesecurity/logwarden/internal/result"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
)

func TestNativeGCSGenerationPreconditionsAndRead(t *testing.T) {
	var conditions []string
	state := State{Status: "delivered", Until: time.Date(2026, 9, 13, 20, 0, 0, 0, time.UTC)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("X-Goog-Generation", "73")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(state)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %s", r.Method)
		}
		conditions = append(conditions, r.URL.Query().Get("ifGenerationMatch"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = w.Write([]byte(`{"error":{"code":412,"message":"generation mismatch"}}`))
	}))
	defer server.Close()
	client, err := storage.NewClient(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	s := GCS{Bucket: client.Bucket("test-state")}
	for _, generation := range []int64{0, 73} {
		if _, err := s.Write(context.Background(), "fixture", generation, state); !errors.Is(err, ErrConflict) {
			t.Fatalf("native SDK conflict not recognized: %v", err)
		}
	}
	if len(conditions) != 2 || conditions[0] != "0" || conditions[1] != "73" {
		t.Fatalf("unsafe conditional upload queries: %v", conditions)
	}
	got, generation, err := s.Read(context.Background(), "fixture")
	if err != nil || generation != 73 || got.Status != "delivered" || !got.Until.Equal(state.Until) {
		t.Fatalf("lost native response generation: %v %d %v", got, generation, err)
	}
}

// Opt-in: writes only a unique synthetic claim and never calls Slack. The bucket's
// lifecycle deletes the tiny status-only object; no real alert key is accessed.
func TestLiveGCSReplicasRestartAndCAS(t *testing.T) {
	bucket := os.Getenv("LOGWARDEN_TEST_STATE_BUCKET")
	if bucket == "" {
		t.Skip("set LOGWARDEN_TEST_STATE_BUCKET for opt-in live CAS proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var opts []option.ClientOption
	if token := os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN"); token != "" {
		opts = append(opts, option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})))
	}
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	s := GCS{Bucket: client.Bucket(bucket)}
	res := result.Result{Rule: "notification_synthetic_cas_" + strconv.FormatInt(time.Now().UnixNano(), 10), Type: "test", Message: "no Slack dispatch", Details: map[string]any{"project": "synthetic"}}
	key := fingerprint(t, res)
	at := time.Now().UTC()
	var sends atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	o := Output{Store: s, Config: Config{RepeatWindowSeconds: 3600}, Now: func() time.Time { return at }, Next: outputFunc(func(context.Context, result.Result) error { sends.Add(1); close(started); <-release; return nil })}
	done := make(chan error, 1)
	go func() { done <- o.Send(ctx, res) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatal("first reservation failed", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replica := o
			if err := replica.Send(ctx, res); !errors.Is(err, ErrInFlight) {
				t.Errorf("replica did not respect durable lease: %v", err)
			}
		}()
	}
	wg.Wait()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// A fresh client simulates process restart, with no in-memory claim cache.
	restartedClient, err := storage.NewClient(ctx, opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restartedClient.Close() }()
	restartedStore := GCS{Bucket: restartedClient.Bucket(bucket)}
	restarted := Output{Store: restartedStore, Config: o.Config, Now: o.Now, Next: outputFunc(func(context.Context, result.Result) error { sends.Add(1); return nil })}
	if err := restarted.Send(ctx, res); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 1 {
		t.Fatal("restarted client repeated delivery")
	}
	state, generation, err := s.Read(ctx, key)
	if err != nil || state.Status != "delivered" {
		t.Fatal("durable delivery outcome missing", err)
	}
	if _, err := s.Write(ctx, key, 0, state); !errors.Is(err, ErrConflict) {
		t.Fatal("DoesNotExist failed to exclude existing object", err)
	}
	if _, err := s.Write(ctx, key, generation-1, state); !errors.Is(err, ErrConflict) {
		t.Fatal("stale generation overwrote existing object", err)
	}
	t.Logf("LIVE_PROOF bucket=%s key_sha256=%s replicas=5 fresh_client=1 fake_deliveries=%d status=%s generation=%d CAS_create_conflict=true CAS_stale_conflict=true Slack_calls=0", bucket, key, sends.Load(), state.Status, generation)
	if state.Until.Sub(at) != time.Hour {
		t.Fatal(fmt.Errorf("unexpected cooldown: %s", state.Until.Sub(at)))
	}
}
