// Package notify gates notification delivery without changing detector/audit output.
package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/trufflesecurity/logwarden/internal/outputs"
	"github.com/trufflesecurity/logwarden/internal/result"
)

var ErrConflict = errors.New("notification claim changed")
var ErrInFlight = errors.New("notification delivery in progress")

type State struct {
	Status     string    `json:"status"`
	Until      time.Time `json:"until"`
	LeaseUntil time.Time `json:"lease_until,omitempty"`
}

type Store interface {
	Read(context.Context, string) (State, int64, error)
	Write(context.Context, string, int64, State) (int64, error)
}

type Output struct {
	Store  Store
	Config Config
	Next   outputs.Output
	Now    func() time.Time
	Audit  func(event, fingerprint string, until time.Time)
}

func (o Output) Send(ctx context.Context, res result.Result) error {
	// Even a slow storage request must finish before another replica may recover
	// this attempt's one-minute lease.
	ctx, cancelSend := context.WithTimeout(ctx, 45*time.Second)
	defer cancelSend()
	at := time.Now().UTC()
	if o.Now != nil {
		at = o.Now().UTC()
	}
	key, err := Fingerprint(res)
	if err != nil {
		return err
	}
	audit := func(event string, until time.Time) {
		if o.Audit != nil {
			o.Audit(event, key, until)
		}
	}
	// An ignored event must never create/extend a claim past the exception's expiry.
	if exception := ExceptionFor(res, o.Config, at); exception != nil {
		until, _ := time.Parse(time.RFC3339, exception.ExpiresAt)
		audit("time_ignored", until)
		return nil
	}
	for attempt := 0; attempt < 8; attempt++ {
		state, generation, err := o.Store.Read(ctx, key)
		if err != nil {
			return fmt.Errorf("read notification claim: %w", err)
		}
		if generation != 0 {
			if state.Until.IsZero() || (state.Status != "reserved" && state.Status != "delivered" && state.Status != "uncertain") {
				return errors.New("invalid durable notification claim")
			}
			if state.Status == "reserved" {
				if state.LeaseUntil.IsZero() {
					return errors.New("notification lease missing")
				}
				// Respect an active lease even if an operator chose a shorter repeat window.
				if at.Before(state.LeaseUntil) {
					return ErrInFlight
				}
			}
			if at.Before(state.Until) {
				if state.Status == "reserved" {
					// A process may have died after Slack accepted the request. Never blindly repost.
					state.Status = "uncertain"
					if _, err = o.Store.Write(ctx, key, generation, state); errors.Is(err, ErrConflict) {
						continue
					} else if err != nil {
						return err
					}
					audit("delivery_uncertain", state.Until)
				} else {
					audit("repeat_suppressed", state.Until)
				}
				return nil
			}
		}
		state = State{Status: "reserved", Until: at.Add(time.Duration(o.Config.RepeatWindowSeconds) * time.Second), LeaseUntil: at.Add(time.Minute)}
		generation, err = o.Store.Write(ctx, key, generation, state)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return fmt.Errorf("reserve notification: %w", err)
		}
		// Bound delivery below the durable lease. Slack has no idempotency key; retain
		// uncertainty on any failed attempt rather than producing a retry flood.
		deliveryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		deliveryErr := o.Next.Send(deliveryCtx, res)
		cancel()
		state.Status = "delivered"
		if deliveryErr != nil {
			state.Status = "uncertain"
		}
		_, commitErr := o.Store.Write(ctx, key, generation, state)
		if commitErr != nil {
			audit("delivery_commit_failed", state.Until)
			return fmt.Errorf("commit notification outcome: %w", commitErr)
		}
		if deliveryErr != nil {
			audit("delivery_uncertain", state.Until)
			return errors.New("notification delivery failed; durable uncertain claim retained")
		}
		audit("delivered", state.Until)
		return nil
	}
	return ErrInFlight
}
