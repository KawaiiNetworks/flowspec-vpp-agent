package main

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vppstats"
)

// agentState is the on-disk snapshot persisted across restarts: detector rule
// history plus VPP stats rings. Encoded with gob.
type agentState struct {
	Detector detector.EngineState
	VPP      vppstats.StoreState
}

// loadState reads a persisted snapshot. A missing file is reported via
// os.IsNotExist(err) so the caller can treat first-run as non-fatal.
func loadState(path string) (agentState, error) {
	f, err := os.Open(path)
	if err != nil {
		return agentState{}, err
	}
	defer f.Close()
	var st agentState
	if err := gob.NewDecoder(f).Decode(&st); err != nil {
		return agentState{}, fmt.Errorf("decode state %s: %w", path, err)
	}
	return st, nil
}

// saveState writes the snapshot atomically (temp file + rename) so a crash mid-
// write never leaves a truncated state file.
func saveState(path string, st agentState) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create state dir: %w", err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if err := gob.NewEncoder(tmp).Encode(st); err != nil {
		tmp.Close()
		return fmt.Errorf("encode state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}
