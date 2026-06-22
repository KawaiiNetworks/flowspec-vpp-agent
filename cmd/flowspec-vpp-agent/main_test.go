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
bgp:
  router_id: 192.0.2.1
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

func TestSplitListen_IPv6(t *testing.T) {
	host, port := splitListen("[2001:db8::1]:10179")
	if host != "2001:db8::1" || port != 10179 {
		t.Fatalf("splitListen IPv6 = %q/%d, want 2001:db8::1/10179", host, port)
	}
}
