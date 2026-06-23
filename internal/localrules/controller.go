package localrules

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

const (
	defaultSession = bgp.SessionID("detector")
	defaultPeer    = "detector"
)

type clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

// Controller turns detector events into manager updates and owns the TTL/refresh
// lifecycle for locally generated FlowSpec rules. In dry-run mode it logs each
// triggered event's description and takes no action.
type Controller struct {
	updates chan<- bgp.Update
	session bgp.SessionID
	peer    string
	log     *slog.Logger
	clock   clock
	leases  map[string]lease
	dryRun  bool

	// advertiser originates detector leases upstream via BGP (nil when BGP is
	// disabled). The export policy restricts delivery to send-peers.
	advertiser bgp.Advertiser

	// latest holds the active-lease snapshot, refreshed whenever leases change
	// and read by status consumers on other goroutines (lock-free).
	latest atomic.Pointer[[]LeaseSnapshot]
}

type lease struct {
	rule      flowspec.Rule
	expiresAt time.Time
}

// LeaseSnapshot is one active synthetic FlowSpec lease: the announced rule and
// when it expires unless refreshed.
type LeaseSnapshot struct {
	EventID   string    `json:"event_id"`
	Family    string    `json:"family"`
	FlowSpec  string    `json:"flowspec"`
	ExpiresAt time.Time `json:"expires_at"`
}

// New creates a local rule lease controller.
func New(updates chan<- bgp.Update, logger *slog.Logger) *Controller {
	if logger == nil {
		logger = slog.Default()
	}
	return &Controller{
		updates: updates,
		session: defaultSession,
		peer:    defaultPeer,
		log:     logger,
		clock:   realClock{},
		leases:  make(map[string]lease),
	}
}

// Run consumes detector events until ctx is cancelled or events is closed.
func (c *Controller) Run(ctx context.Context, events <-chan detector.Event) {
	timer := c.clock.After(nextWake(c.clock.Now(), c.leases))
	for {
		select {
		case <-ctx.Done():
			c.withdrawAll(ctx)
			return
		case ev, ok := <-events:
			if !ok {
				c.withdrawAll(ctx)
				return
			}
			c.applyEvent(ctx, ev)
			timer = c.clock.After(nextWake(c.clock.Now(), c.leases))
		case <-timer:
			c.expire(ctx, c.clock.Now())
			timer = c.clock.After(nextWake(c.clock.Now(), c.leases))
		}
	}
}

// SetDryRun enables dry-run mode: triggered events are logged but never
// announced, refreshed, or withdrawn.
func (c *Controller) SetDryRun(v bool) { c.dryRun = v }

// SetAdvertiser sets the BGP advertiser used to originate detector leases
// upstream. Nil (the default) disables advertisement.
func (c *Controller) SetAdvertiser(a bgp.Advertiser) { c.advertiser = a }

// advertise originates or withdraws a rule upstream via BGP. Failures are logged
// but never block the VPP-facing lease lifecycle.
func (c *Controller) advertise(ctx context.Context, r flowspec.Rule, withdraw bool) {
	if c.advertiser == nil {
		return
	}
	if err := c.advertiser.Advertise(ctx, r, withdraw); err != nil {
		c.log.Warn("advertise detector flowspec upstream",
			"withdraw", withdraw, "flowspec", r.Raw, "error", err)
	}
}

// Snapshot returns the currently active leases. Safe to call from any goroutine.
func (c *Controller) Snapshot() []LeaseSnapshot {
	if s := c.latest.Load(); s != nil {
		return *s
	}
	return nil
}

// publish rebuilds the lease snapshot. Called on the Run goroutine after any
// lease mutation, so the stored slice is never shared with a mutating caller.
func (c *Controller) publish() {
	out := make([]LeaseSnapshot, 0, len(c.leases))
	for id, l := range c.leases {
		out = append(out, LeaseSnapshot{
			EventID:   id,
			Family:    l.rule.Family.String(),
			FlowSpec:  l.rule.Raw,
			ExpiresAt: l.expiresAt,
		})
	}
	c.latest.Store(&out)
}

func (c *Controller) applyEvent(ctx context.Context, ev detector.Event) {
	if ev.TTL <= 0 {
		return
	}
	if c.dryRun {
		c.log.Info("dry-run: detector event (no action taken)",
			"event", ev.ID, "ttl", ev.TTL.String(), "description", ev.Description)
		return
	}
	now := c.clock.Now()
	expiresAt := now.Add(ev.TTL)
	old, exists := c.leases[ev.ID]
	if exists && sameRule(old.rule, ev.Rule) {
		if ev.Refresh {
			old.expiresAt = expiresAt
			c.leases[ev.ID] = old
			c.publish()
		}
		c.log.Debug("detector rule refreshed",
			"event", ev.ID, "ttl", ev.TTL.String(), "description", ev.Description)
		return
	}
	c.leases[ev.ID] = lease{rule: ev.Rule, expiresAt: expiresAt}
	if exists {
		c.send(ctx, bgp.Update{Session: c.session, Peer: c.peer, Op: bgp.OpWithdraw, Rule: &old.rule})
		c.advertise(ctx, old.rule, true)
	}
	c.send(ctx, bgp.Update{Session: c.session, Peer: c.peer, Op: bgp.OpAnnounce, Rule: &ev.Rule})
	c.advertise(ctx, ev.Rule, false)
	c.publish()
	c.log.Info("detector rule announced",
		"event", ev.ID, "ttl", ev.TTL.String(), "description", ev.Description)
}

func (c *Controller) expire(ctx context.Context, now time.Time) {
	changed := false
	for id, l := range c.leases {
		if now.Before(l.expiresAt) {
			continue
		}
		r := l.rule
		delete(c.leases, id)
		changed = true
		c.send(ctx, bgp.Update{Session: c.session, Peer: c.peer, Op: bgp.OpWithdraw, Rule: &r})
		c.advertise(ctx, r, true)
		c.log.Info("detector rule expired", "event", id)
	}
	if changed {
		c.publish()
	}
}

func (c *Controller) withdrawAll(ctx context.Context) {
	for id, l := range c.leases {
		r := l.rule
		delete(c.leases, id)
		c.send(ctx, bgp.Update{Session: c.session, Peer: c.peer, Op: bgp.OpWithdraw, Rule: &r})
		c.advertise(ctx, r, true)
	}
	c.publish()
}

func (c *Controller) send(ctx context.Context, u bgp.Update) bool {
	select {
	case c.updates <- u:
		return true
	case <-ctx.Done():
		return false
	}
}

func sameRule(a, b flowspec.Rule) bool {
	return a.Raw == b.Raw
}

func nextWake(now time.Time, leases map[string]lease) time.Duration {
	if len(leases) == 0 {
		return time.Hour
	}
	var next time.Time
	for _, l := range leases {
		if next.IsZero() || l.expiresAt.Before(next) {
			next = l.expiresAt
		}
	}
	if d := next.Sub(now); d > 0 {
		return d
	}
	return time.Nanosecond
}
