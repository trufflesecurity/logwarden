package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNotificationPolicyRejectsMalformedAndOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	for _, body := range [][]byte{[]byte(`{"repeat_window_seconds":0}`), make([]byte, 65537)} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadNotificationPolicy(context.Background(), nil, path); err == nil {
			t.Fatal("invalid startup policy accepted")
		}
	}
	if err := os.WriteFile(path, []byte(`{"repeat_window_seconds":3600}`), 0600); err != nil {
		t.Fatal(err)
	}
	if config, err := loadNotificationPolicy(context.Background(), nil, path); err != nil || config.RepeatWindowSeconds != 3600 {
		t.Fatal(config, err)
	}
}

func TestDeploymentNotificationPolicy(t *testing.T) {
	path := os.Getenv("LOGWARDEN_TEST_POLICY")
	if path == "" {
		t.Skip("set LOGWARDEN_TEST_POLICY to validate an actual deployment policy")
	}
	config, err := loadNotificationPolicy(context.Background(), nil, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("deployment policy valid: repeat_window_seconds=%d exceptions=%d", config.RepeatWindowSeconds, len(config.Exceptions))
}
