package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunHealthcheck_MetricsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`metrics:
  listen: ""
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runHealthcheck([]string{"-config", path}); code != 0 {
		t.Fatalf("healthcheck with disabled metrics = %d, want 0", code)
	}
}

func TestRunHealthcheck_ConfigError(t *testing.T) {
	if code := runHealthcheck([]string{"-config", "/no/such/config.yaml"}); code == 0 {
		t.Fatal("healthcheck with missing config succeeded, want failure")
	}
}
