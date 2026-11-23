package notify

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/logwarden/internal/result"
)

const policyJSON = `{"repeat_window_seconds":3600,"exceptions":[{"id":"db-cleaner-shared3-20260913","starts_at":"2026-09-13T18:20:56Z","expires_at":"2026-09-20T18:20:56Z","match":{"Rule":"cloud_sql_connect","Type":"violation","Message":"unexpected connection to cloudsql instance","Details":{"instance":"thog-prod:shared3","project":"thog-prod","actor":"db-cleaner@thog-prod.iam.gserviceaccount.com"}}}]}`

func fixture(t *testing.T) (Config, result.Result) {
	t.Helper()
	config, err := ParseConfig([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(config.Exceptions[0].Match)
	var res result.Result
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	return config, res
}

func fingerprint(t *testing.T, res result.Result) string {
	t.Helper()
	key, err := Fingerprint(res)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestExactExceptionIntervalAndScope(t *testing.T) {
	config, res := fixture(t)
	start, _ := time.Parse(time.RFC3339, config.Exceptions[0].StartsAt)
	end, _ := time.Parse(time.RFC3339, config.Exceptions[0].ExpiresAt)
	for _, test := range []struct {
		at   time.Time
		want bool
	}{{start.Add(-time.Nanosecond), false}, {start, true}, {end.Add(-time.Nanosecond), true}, {end, false}, {end.Add(time.Hour), false}} {
		if ignored := ExceptionFor(res, config, test.at) != nil; ignored != test.want {
			t.Fatalf("at %s: ignored=%t, want %t", test.at, ignored, test.want)
		}
	}
	res.Details["timestamp"] = start.Format(time.RFC3339)
	if ExceptionFor(res, config, end) != nil {
		t.Fatal("stale event timestamp extended exception")
	}
	original := fingerprint(t, res)
	for _, field := range []string{"Rule", "Type", "Message", "instance", "project", "actor"} {
		t.Run(field, func(t *testing.T) {
			_, changed := fixture(t)
			switch field {
			case "Rule":
				changed.Rule += "-different"
			case "Type":
				changed.Type += "-different"
			case "Message":
				changed.Message += "-different"
			default:
				changed.Details[field] = changed.Details[field].(string) + "-different"
			}
			if ExceptionFor(changed, config, start) != nil || fingerprint(t, changed) == original {
				t.Fatal("changed scope was ignored or shared its fingerprint")
			}
		})
	}
}

func TestFingerprintOnlyOmitsTopLevelOccurrenceFields(t *testing.T) {
	_, res := fixture(t)
	original := fingerprint(t, res)
	for _, key := range []string{"link", "insertId", "timestamp"} {
		res.Details[key] = "new occurrence"
	}
	if fingerprint(t, res) != original || res.Details["link"] != "new occurrence" {
		t.Fatal("volatile fields changed fingerprint or original result was mutated")
	}
	res.Details["nested"] = map[string]any{"z": 1, "timestamp": "first", "a": []any{"x", "y"}}
	first := fingerprint(t, res)
	res.Details["nested"] = map[string]any{"a": []any{"x", "y"}, "timestamp": "first", "z": 1}
	if fingerprint(t, res) != first || first == original {
		t.Fatal("key ordering changed fingerprint or added detail was lost")
	}
	res.Details["nested"].(map[string]any)["timestamp"] = "different"
	if fingerprint(t, res) == first {
		t.Fatal("nested timestamp was incorrectly omitted")
	}
	res.Details["nested"] = map[string]any{"a": []any{"y", "x"}, "timestamp": "first", "z": 1}
	if fingerprint(t, res) == first {
		t.Fatal("array ordering was lost")
	}
	res.Details["invalid"] = math.NaN()
	if _, err := Fingerprint(res); err == nil {
		t.Fatal("invalid JSON value accepted")
	}
}

func TestConfigRejectsUnboundedOrAmbiguousSuppression(t *testing.T) {
	config, err := ParseConfig([]byte(`{}`))
	if err != nil || config.RepeatWindowSeconds != 3600 || len(config.Exceptions) != 0 {
		t.Fatal("incorrect defaults", config, err)
	}
	for _, value := range []string{"null", "0", "-1", "86401", "1.5", "1e999", `"3600"`} {
		if _, err := ParseConfig([]byte(`{"repeat_window_seconds":` + value + `}`)); err == nil {
			t.Fatalf("invalid duration accepted: %s", value)
		}
	}
	for _, value := range []string{"1", "86400"} {
		if _, err := ParseConfig([]byte(`{"repeat_window_seconds":` + value + `}`)); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{
		`null`, `[]`, policyJSON + `{}`,
		strings.Replace(policyJSON, `"expires_at":"2026-09-20T18:20:56Z"`, `"expires_at":"2026-09-20T18:20:57Z"`, 1),
		strings.Replace(policyJSON, "2026-09-20T18:20:56Z", "2026-09-13T18:20:56Z", 1),
		strings.Replace(policyJSON, "2026-09-20T18:20:56Z", "2026-09-12T18:20:56Z", 1),
		strings.Replace(policyJSON, "2026-09-20T18:20:56Z", "2026-09-20T18:20:56+00:00", 1),
		strings.Replace(policyJSON, "2026-09-20T18:20:56Z", "2026-09-20T18:20:56.000Z", 1),
		strings.Replace(policyJSON, "2026-09-20T18:20:56Z", "2026-02-30T18:20:56Z", 1),
		strings.Replace(policyJSON, `"actor":"db-cleaner@thog-prod.iam.gserviceaccount.com"`, `"actor":null`, 1),
		strings.Replace(policyJSON, `"actor":"db-cleaner@thog-prod.iam.gserviceaccount.com"`, `"actor":""`, 1),
		strings.Replace(policyJSON, `"actor":"db-cleaner@thog-prod.iam.gserviceaccount.com"`, `"unexpected":"actor"`, 1),
		strings.Replace(policyJSON, `"repeat_window_seconds":3600`, `"unknown":3600`, 1),
	} {
		if _, err := ParseConfig([]byte(invalid)); err == nil {
			t.Fatalf("invalid config accepted: %s", invalid)
		}
	}
	config, _ = ParseConfig([]byte(policyJSON))
	config.Exceptions = append(config.Exceptions, config.Exceptions[0])
	duplicate, _ := json.Marshal(config)
	if _, err := ParseConfig(duplicate); err == nil {
		t.Fatal("duplicate exception ID accepted")
	}
}
