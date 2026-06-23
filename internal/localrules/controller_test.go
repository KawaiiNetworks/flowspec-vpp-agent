package localrules

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
	ch  chan time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, ch: make(chan time.Time, 8)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}
func (f *fakeClock) After(time.Duration) <-chan time.Time {
	return f.ch
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	now := f.now
	f.mu.Unlock()
	f.ch <- now
}

func TestControllerAnnounceRefreshExpire(t *testing.T) {
	updates := make(chan bgp.Update, 8)
	events := make(chan detector.Event, 8)
	clk := newFakeClock(time.Unix(1000, 0))
	c := New(updates, nil)
	c.clock = clk

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.Run(ctx, events)
		close(done)
	}()

	ev := detector.Event{
		ID:      "rule/src=198.51.100.9",
		TTL:     10 * time.Second,
		Refresh: true,
		Rule: flowspec.Rule{
			Family: flowspec.FamilyIPv4,
			Match: flowspec.Match{
				HasSrc: true,
				Src:    netip.MustParsePrefix("198.51.100.9/32"),
			},
			Action: flowspec.Action{Kind: flowspec.ActionDrop},
			Raw:    "detector:rule:src=198.51.100.9",
		},
	}
	events <- ev
	u := <-updates
	if u.Op != bgp.OpAnnounce || u.Session != defaultSession {
		t.Fatalf("first update = %+v, want local announce", u)
	}

	clk.advance(5 * time.Second)
	events <- ev
	select {
	case u := <-updates:
		t.Fatalf("refresh emitted update %+v, want no manager churn", u)
	case <-time.After(20 * time.Millisecond):
	}

	clk.advance(9 * time.Second)
	select {
	case u := <-updates:
		t.Fatalf("early expiry emitted update %+v", u)
	case <-time.After(20 * time.Millisecond):
	}

	clk.advance(2 * time.Second)
	u = <-updates
	if u.Op != bgp.OpWithdraw {
		t.Fatalf("expiry update = %+v, want withdraw", u)
	}
	cancel()
	<-done
}

func TestControllerSnapshot(t *testing.T) {
	updates := make(chan bgp.Update, 8)
	clk := newFakeClock(time.Unix(1000, 0))
	c := New(updates, nil)
	c.clock = clk
	ctx := context.Background()

	if len(c.Snapshot()) != 0 {
		t.Fatalf("snapshot non-empty before any event")
	}

	ev := detector.Event{
		ID:      "rule/src=198.51.100.9",
		TTL:     10 * time.Second,
		Refresh: true,
		Rule: flowspec.Rule{
			Family: flowspec.FamilyIPv4,
			Action: flowspec.Action{Kind: flowspec.ActionDrop},
			Raw:    "detector:rule:src=198.51.100.9",
		},
	}
	// Drive applyEvent/expire synchronously (updates is buffered) so the snapshot
	// is observed deterministically without the Run goroutine.
	c.applyEvent(ctx, ev)
	snap := c.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot = %d leases, want 1", len(snap))
	}
	if snap[0].EventID != ev.ID || snap[0].FlowSpec != ev.Rule.Raw {
		t.Fatalf("lease snapshot = %+v", snap[0])
	}
	if snap[0].Family != flowspec.FamilyIPv4.String() {
		t.Fatalf("lease family = %q, want %q", snap[0].Family, flowspec.FamilyIPv4.String())
	}
	if !snap[0].ExpiresAt.Equal(clk.Now().Add(ev.TTL)) {
		t.Fatalf("expiresAt = %v", snap[0].ExpiresAt)
	}

	clk.advance(11 * time.Second)
	c.expire(ctx, clk.Now())
	if len(c.Snapshot()) != 0 {
		t.Fatalf("snapshot non-empty after expiry")
	}
}

func TestControllerDryRunTakesNoAction(t *testing.T) {
	updates := make(chan bgp.Update, 8)
	events := make(chan detector.Event, 8)
	clk := newFakeClock(time.Unix(1000, 0))
	c := New(updates, nil)
	c.clock = clk
	c.SetDryRun(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.Run(ctx, events)
		close(done)
	}()

	events <- detector.Event{
		ID:          "rule/src=198.51.100.9",
		TTL:         10 * time.Second,
		Refresh:     true,
		Description: "test event",
		Rule: flowspec.Rule{
			Family: flowspec.FamilyIPv4,
			Match:  flowspec.Match{HasSrc: true, Src: netip.MustParsePrefix("198.51.100.9/32")},
			Action: flowspec.Action{Kind: flowspec.ActionDrop},
			Raw:    "detector:rule:src=198.51.100.9",
		},
	}
	select {
	case u := <-updates:
		t.Fatalf("dry-run emitted update %+v, want none", u)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	<-done
}
