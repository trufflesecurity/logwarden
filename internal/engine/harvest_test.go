package engine

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2"
	pb "cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"cloud.google.com/go/pubsub/v2/pstest"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	testTopic = "projects/P/topics/T"
	testSub   = "projects/P/subscriptions/S"
)

// fakeSubscriber stands up an in-process Pub/Sub carrying the given payloads and returns a
// subscriber attached to it.
func fakeSubscriber(t *testing.T, payloads ...string) (*pubsub.Subscriber, *pstest.Server) {
	t.Helper()

	// Otherwise every drained-subscription test sits through the real idle window.
	restore := harvestIdle
	harvestIdle = 200 * time.Millisecond
	t.Cleanup(func() { harvestIdle = restore })

	srv := pstest.NewServer()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := grpc.NewClient(srv.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, "P", option.WithGRPCConn(conn))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if _, err := client.TopicAdminClient.CreateTopic(ctx, &pb.Topic{Name: testTopic}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubscriptionAdminClient.CreateSubscription(ctx, &pb.Subscription{
		Name:  testSub,
		Topic: testTopic,
	}); err != nil {
		t.Fatal(err)
	}

	for _, p := range payloads {
		srv.Publish(testTopic, []byte(p), nil)
	}

	return client.Subscriber(testSub), srv
}

func repeat(n int, payload string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = payload
	}
	return out
}

// Every message is nacked and comes straight back, so the limit and the per-message dedup
// are the only things keeping harvest from writing the same event over and over.
func TestHarvestStopsAtLimitAndDeduplicates(t *testing.T) {
	sub, _ := fakeSubscriber(t, repeat(50, `{"insertId":"i"}`)...)

	var buf bytes.Buffer
	n, err := harvest(context.Background(), sub, 10, &buf)
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	if n != 10 {
		t.Errorf("captured %d, want 10", n)
	}
	if lines := strings.Count(buf.String(), "\n"); lines != 10 {
		t.Errorf("wrote %d lines, want 10", lines)
	}
}

type failingWriter struct{ calls, failAt int }

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls >= w.failAt {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

// A write failure used to be swallowed: cancel() made ctx.Err() non-nil, so the Receive
// error was discarded and harvest reported success over a truncated capture.
func TestHarvestReportsWriteErrors(t *testing.T) {
	sub, _ := fakeSubscriber(t, repeat(20, `{"insertId":"i"}`)...)

	_, err := harvest(context.Background(), sub, 10, &failingWriter{failAt: 3})
	if err == nil {
		t.Fatal("expected the write error to surface, got nil")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Errorf("error = %v, want it to wrap the write failure", err)
	}
}

// With fewer messages than --limit, harvest must return once the subscription stops
// yielding anything new rather than re-nacking the same few until the timeout.
func TestHarvestStopsWhenSubscriptionIsDrained(t *testing.T) {
	sub, _ := fakeSubscriber(t, `{"insertId":"a"}`, `{"insertId":"b"}`)

	var buf bytes.Buffer
	n, err := harvest(context.Background(), sub, 500, &buf)
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	if n != 2 {
		t.Errorf("captured %d, want 2 (one per distinct message)", n)
	}
}

// A payload that is not JSON must be reported once, not on every redelivery for the rest
// of the window, and must not stop the messages around it being captured.
func TestHarvestSkipsUnparseablePayloadOnce(t *testing.T) {
	sub, _ := fakeSubscriber(t, `{"insertId":"a"}`, `not json`, `{"insertId":"b"}`)

	var buf bytes.Buffer
	n, err := harvest(context.Background(), sub, 500, &buf)
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	if n != 2 {
		t.Errorf("captured %d, want 2 (the unparseable payload skipped)", n)
	}
}

func TestHarvestRejectsNonPositiveLimit(t *testing.T) {
	if _, err := harvest(context.Background(), nil, 0, &bytes.Buffer{}); err == nil {
		t.Fatal("expected an error for limit 0")
	}
}

// The idle timer must not run before anything has arrived. It used to be armed as soon as
// Receive started, so a subscription that was quiet for harvestIdle gave up with zero
// events -- and --timeout never governed the wait for the first one.
func TestHarvestWaitsForTheFirstMessage(t *testing.T) {
	sub, srv := fakeSubscriber(t)

	go func() {
		time.Sleep(4 * harvestIdle)
		srv.Publish(testTopic, []byte(`{"insertId":"late"}`), nil)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 40*harvestIdle)
	defer cancel()

	var buf bytes.Buffer
	n, err := harvest(ctx, sub, 500, &buf)
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	if n != 1 {
		t.Errorf("captured %d, want 1: harvest gave up before the first message arrived", n)
	}
}
