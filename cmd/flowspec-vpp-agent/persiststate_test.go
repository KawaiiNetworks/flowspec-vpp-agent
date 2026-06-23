package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
)

func TestSaveLoadState_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.gob") // sub dir is created by saveState
	want := agentState{
		Detector: detector.EngineState{Rules: []detector.RuleState{{Name: "udp-flood-ipv4"}}},
	}
	if err := saveState(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Detector.Rules) != 1 || got.Detector.Rules[0].Name != "udp-flood-ipv4" {
		t.Fatalf("round-trip = %+v", got.Detector.Rules)
	}
}

func TestLoadState_MissingIsNotExist(t *testing.T) {
	_, err := loadState(filepath.Join(t.TempDir(), "absent.gob"))
	if !os.IsNotExist(err) {
		t.Fatalf("missing state error = %v, want os.IsNotExist", err)
	}
}
