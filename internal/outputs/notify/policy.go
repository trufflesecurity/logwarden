package notify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/trufflesecurity/logwarden/internal/result"
)

type Config struct {
	RepeatWindowSeconds int         `json:"repeat_window_seconds"`
	Exceptions          []Exception `json:"exceptions"`
}

type Exception struct {
	ID        string        `json:"id"`
	StartsAt  string        `json:"starts_at"`
	ExpiresAt string        `json:"expires_at"`
	Match     result.Result `json:"match"`
}

// ParseConfig rejects invalid policy rather than silently extending suppression.
func ParseConfig(data []byte) (Config, error) {
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return Config{}, fmt.Errorf("notification config must be an object")
	}
	var raw struct {
		RepeatWindowSeconds json.RawMessage `json:"repeat_window_seconds"`
		Exceptions          []Exception     `json:"exceptions"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Config{}, fmt.Errorf("notification config must contain exactly one JSON object")
	}
	config := Config{RepeatWindowSeconds: 3600, Exceptions: raw.Exceptions}
	if len(raw.RepeatWindowSeconds) != 0 {
		config.RepeatWindowSeconds = 0
		if err := json.Unmarshal(raw.RepeatWindowSeconds, &config.RepeatWindowSeconds); err != nil {
			return Config{}, err
		}
	}
	if config.RepeatWindowSeconds < 1 || config.RepeatWindowSeconds > 86400 {
		return Config{}, fmt.Errorf("repeat_window_seconds must be an integer from 1 to 86400")
	}
	seen := map[string]bool{}
	for _, exception := range config.Exceptions {
		if exception.ID == "" || seen[exception.ID] {
			return Config{}, fmt.Errorf("exception IDs must be nonempty and unique")
		}
		seen[exception.ID] = true
		start, startErr := exactUTC(exception.StartsAt)
		end, endErr := exactUTC(exception.ExpiresAt)
		if startErr != nil || endErr != nil || !end.After(start) || end.Sub(start) > 7*24*time.Hour {
			return Config{}, fmt.Errorf("exception %q requires exact UTC seconds and a positive interval of at most seven days", exception.ID)
		}
		match := exception.Match
		if match.Rule == "" || match.Type == "" || match.Message == "" || len(match.Details) != 3 {
			return Config{}, fmt.Errorf("exception %q requires rule, type, message, project, actor and instance", exception.ID)
		}
		for _, key := range []string{"project", "actor", "instance"} {
			if value, ok := match.Details[key].(string); !ok || value == "" {
				return Config{}, fmt.Errorf("exception %q requires nonempty %s", exception.ID, key)
			}
		}
	}
	return config, nil
}

func exactUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, fmt.Errorf("expected YYYY-MM-DDTHH:MM:SSZ")
	}
	return parsed, nil
}

// ExceptionFor uses notification time; stale event timestamps cannot extend an exception.
func ExceptionFor(res result.Result, config Config, now time.Time) *Exception {
	for i := range config.Exceptions {
		exception := &config.Exceptions[i]
		start, startErr := exactUTC(exception.StartsAt)
		end, endErr := exactUTC(exception.ExpiresAt)
		if startErr != nil || endErr != nil || now.Before(start) || !now.Before(end) {
			continue
		}
		match := exception.Match
		if res.Rule != match.Rule || res.Type != match.Type || res.Message != match.Message {
			continue
		}
		equal := true
		for _, key := range []string{"project", "actor", "instance"} {
			value, ok := res.Details[key].(string)
			if !ok || value != match.Details[key] {
				equal = false
			}
		}
		if equal {
			return exception
		}
	}
	return nil
}

// Fingerprint retains all semantic fields, including nested occurrence-like keys.
// encoding/json sorts map keys recursively; copying preserves the original result.
func Fingerprint(res result.Result) (string, error) {
	if res.Details != nil {
		details := make(map[string]any, len(res.Details))
		for key, value := range res.Details {
			if key != "link" && key != "insertId" && key != "timestamp" {
				details[key] = value
			}
		}
		res.Details = details
	}
	data, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
