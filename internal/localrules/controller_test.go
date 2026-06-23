package localrules

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

type fakeClock struct {
	now time.Time
	ch  chan time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, ch: make(chan time.Time, 8)}
}

func (f *fakeClock) Now() time.Time { return f.now }
func (f *fakeClock) After(time.Duration) <-chan time.Time {
	return f.ch
}

func (f *fakeClock) advance(d time.Duration) {
	f.now = f.now.Add(d)
	f.ch <- f.now
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
			Raw:    "local-detector:rule:src=198.51.100.9",
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
			Raw:    "local-detector:rule:src=198.51.100.9",
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
