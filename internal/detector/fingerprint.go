package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ruleFingerprint is a stable hash of a rule's full configuration. Persisted
// history is only reloaded into a rule whose fingerprint still matches, so any
// edit to a rule's definition — match, aggregate, history sizing (including
// max_instances), trigger, flowspec, rank, or description — makes that rule start
// fresh instead of inheriting history that may no longer mean the same thing.
//
// RuleConfig is plain data (no pointers, no unexported fields), and encoding/json
// emits map keys in sorted order, so the hash is deterministic across runs.
func ruleFingerprint(cfg RuleConfig) string {
	b, err := json.Marshal(cfg)
	if err != nil {
		// Cannot realistically happen for plain data; fall back to a per-name token
		// so a rule never silently reloads another rule's history.
		return "unmarshalable:" + cfg.Name
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
