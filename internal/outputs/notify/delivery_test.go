package notify

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trufflesecurity/logwarden/internal/result"
)

type outputFunc func(context.Context, result.Result) error

func (f outputFunc) Send(ctx context.Context, res result.Result) error { return f(ctx, res) }

// One store represents shared, persistent state across distinct output instances.
type memoryStore struct {
	sync.Mutex
	states        map[string]State
	versions      map[string]int64
	reads, writes int
	readErr       error
	writeErrAt    int
}

func newStore() *memoryStore {
	return &memoryStore{states: map[string]State{}, versions: map[string]int64{}}
}
func (s *memoryStore) Read(_ context.Context, key string) (State, int64, error) {
	s.Lock()
	defer s.Unlock()
	s.reads++
	return s.states[key], s.versions[key], s.readErr
}
func (s *memoryStore) Write(_ context.Context, key string, generation int64, state State) (int64, error) {
	s.Lock()
	defer s.Unlock()
	s.writes++
	if s.writes == s.writeErrAt {
		return 0, errors.New("storage unavailable")
	}
	if s.versions[key] != generation {
		return 0, ErrConflict
	}
	s.versions[key]++
	s.states[key] = state
	return s.versions[key], nil
}

func TestConcurrentReplicasAndRestartDeliverOncePerWindow(t *testing.T) {
	config, res := fixture(t)
	config.Exceptions = nil
	at := time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)
	s := newStore()
	var sends atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	next := outputFunc(func(ctx context.Context, _ result.Result) error {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 20*time.Second {
			t.Error("delivery timeout missing")
		}
		sends.Add(1)
		close(started)
		<-release
		return nil
	})
	one := Output{Store: s, Config: config, Next: next, Now: func() time.Time { return at }}
	done := make(chan error, 1)
	go func() { done <- one.Send(context.Background(), res) }()
	<-started
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replica := one
			if err := replica.Send(context.Background(), res); !errors.Is(err, ErrInFlight) {
				t.Errorf("expected live lease refusal, got %v", err)
			}
		}()
	}
	wg.Wait()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	restarted := Output{Store: s, Config: config, Next: outputFunc(func(context.Context, result.Result) error { sends.Add(1); return nil }), Now: func() time.Time { return at.Add(time.Hour - time.Nanosecond) }}
	res.Details["link"] = "new audit occurrence"
	if err := restarted.Send(context.Background(), res); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 1 {
		t.Fatal("restart or occurrence link bypassed dedupe")
	}
	restarted.Now = func() time.Time { return at.Add(time.Hour) }
	if err := restarted.Send(context.Background(), res); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 2 {
		t.Fatal("window expiry did not permit notification")
	}
	res.Details["actor"] = "unrelated@example.com"
	if err := restarted.Send(context.Background(), res); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 3 {
		t.Fatal("unrelated actor shared suppression")
	}
}

func TestIgnoreNeverTouchesClaimAndExpiresImmediately(t *testing.T) {
	config, res := fixture(t)
	start, _ := time.Parse(time.RFC3339, config.Exceptions[0].StartsAt)
	end, _ := time.Parse(time.RFC3339, config.Exceptions[0].ExpiresAt)
	s := newStore()
	sends := 0
	o := Output{Store: s, Config: config, Next: outputFunc(func(context.Context, result.Result) error { sends++; return nil })}
	for _, at := range []time.Time{start, end.Add(-time.Nanosecond)} {
		o.Now = func() time.Time { return at }
		if err := o.Send(context.Background(), res); err != nil {
			t.Fatal(err)
		}
	}
	if s.reads != 0 || s.writes != 0 || sends != 0 {
		t.Fatal("active exception accessed claims or delivered")
	}
	// An old event timestamp cannot carry the exception beyond trusted processing time.
	res.Details["timestamp"] = start.Format(time.RFC3339)
	o.Now = func() time.Time { return end }
	if err := o.Send(context.Background(), res); err != nil {
		t.Fatal(err)
	}
	if sends != 1 || s.writes != 2 {
		t.Fatal("first alert at exact expiry did not deliver and commit")
	}
}

func TestStorageFailuresPreventSendAndCommitFailureRetainsUncertainty(t *testing.T) {
	config, res := fixture(t)
	config.Exceptions = nil
	at := time.Now().UTC()
	for _, failure := range []string{"read", "reserve", "commit"} {
		t.Run(failure, func(t *testing.T) {
			s := newStore()
			calls := 0
			if failure == "read" {
				s.readErr = errors.New("storage offline")
			}
			if failure == "reserve" {
				s.writeErrAt = 1
			}
			if failure == "commit" {
				s.writeErrAt = 2
			}
			o := Output{Store: s, Config: config, Now: func() time.Time { return at }, Next: outputFunc(func(context.Context, result.Result) error { calls++; return nil })}
			if err := o.Send(context.Background(), res); err == nil {
				t.Fatal("storage failure acknowledged")
			}
			if failure != "commit" {
				if calls != 0 {
					t.Fatal("notification sent without durable claim")
				}
				return
			}
			if calls != 1 {
				t.Fatal("delivery not attempted")
			}
			key := fingerprint(t, res)
			if s.states[key].Status != "reserved" {
				t.Fatal("failed commit lost reservation")
			}
			if err := o.Send(context.Background(), res); !errors.Is(err, ErrInFlight) {
				t.Fatal("active failed-commit lease bypassed", err)
			}
			o.Now = func() time.Time { return at.Add(time.Minute) }
			if err := o.Send(context.Background(), res); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || s.states[key].Status != "uncertain" {
				t.Fatal("crash recovery blindly resent uncertain notification")
			}
		})
	}
}

func TestUncertainDeliverySuppressesRetryButNotNewWindow(t *testing.T) {
	config, res := fixture(t)
	config.Exceptions = nil
	at := time.Now().UTC()
	s := newStore()
	calls := 0
	o := Output{Store: s, Config: config, Now: func() time.Time { return at }, Next: outputFunc(func(context.Context, result.Result) error { calls++; return errors.New("webhook may have accepted") })}
	if err := o.Send(context.Background(), res); err == nil {
		t.Fatal("first delivery failure did not propagate")
	}
	if s.states[fingerprint(t, res)].Status != "uncertain" {
		t.Fatal("ambiguous delivery not distinguished")
	}
	if err := o.Send(context.Background(), res); err != nil {
		t.Fatal("durable uncertain retry must suppress flood", err)
	}
	if calls != 1 {
		t.Fatal("uncertain notification was immediately resent")
	}
	o.Now = func() time.Time { return at.Add(time.Hour) }
	if err := o.Send(context.Background(), res); err == nil || calls != 2 {
		t.Fatal("new window did not retry")
	}
}

func TestShortRepeatWindowCannotOverrideActiveLease(t *testing.T) {
	config, res := fixture(t)
	config.Exceptions = nil
	config.RepeatWindowSeconds = 1
	at := time.Now().UTC()
	s := newStore()
	key := fingerprint(t, res)
	s.states[key] = State{Status: "reserved", Until: at.Add(-time.Second), LeaseUntil: at.Add(time.Second)}
	s.versions[key] = 1
	o := Output{Store: s, Config: config, Now: func() time.Time { return at }, Next: outputFunc(func(context.Context, result.Result) error { t.Fatal("overlapped active sender"); return nil })}
	if err := o.Send(context.Background(), res); !errors.Is(err, ErrInFlight) {
		t.Fatal(err)
	}
}
