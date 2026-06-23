package detector

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

// Snapshot is served on demand from the run goroutine: it reflects folded samples
// and, once the runner stops, returns empty without blocking.
func TestRunner_SnapshotOnDemand(t *testing.T) {
	rules, err := CompileConfig([]byte(udpFloodYAML))
	if err != nil {
		t.Fatal(err)
	}
	samples := make(chan Sample, 4)
	events := make(chan Event, 4)
	r := NewRunner(NewEngine(rules), samples, events, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	samples <- Sample{
		At: time.Now(), Family: flowspec.FamilyIPv4,
		Src: netip.MustParseAddr("198.51.100.9"), Dst: netip.MustParseAddr("203.0.113.10"),
		Proto: protoUDP, PacketLen: 80, SampleRate: 1000,
	}

	// The sample and the snapshot request race on the run loop's select, so retry
	// briefly until the sample has been folded into an instance.
	var snap EngineSnapshot
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap = r.Snapshot()
		if len(snap.Rules) == 1 && snap.Rules[0].InstanceCount == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if len(snap.Rules) != 1 || snap.Rules[0].InstanceCount != 1 {
		t.Fatalf("on-demand snapshot = %+v, want 1 rule with 1 instance", snap.Rules)
	}

	cancel()
	<-done
	if got := r.Snapshot(); len(got.Rules) != 0 {
		t.Fatalf("post-stop snapshot rules = %d, want 0 (must not block)", len(got.Rules))
	}
}
