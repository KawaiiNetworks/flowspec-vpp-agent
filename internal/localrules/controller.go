package localrules

import (
	"context"
	"log/slog"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/flowspec"
)

const (
	defaultSession = bgp.SessionID("local-detector")
	defaultPeer    = "local-detector"
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
}

type lease struct {
	rule      flowspec.Rule
	expiresAt time.Time
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
		}
		c.log.Debug("local detector rule refreshed",
			"event", ev.ID, "ttl", ev.TTL.String(), "description", ev.Description)
		return
	}
	c.leases[ev.ID] = lease{rule: ev.Rule, expiresAt: expiresAt}
	if exists {
		c.send(ctx, bgp.Update{Session: c.session, Peer: c.peer, Op: bgp.OpWithdraw, Rule: &old.rule})
	}
	c.send(ctx, bgp.Update{Session: c.session, Peer: c.peer, Op: bgp.OpAnnounce, Rule: &ev.Rule})
	c.log.Info("local detector rule announced",
		"event", ev.ID, "ttl", ev.TTL.String(), "description", ev.Description)
}

func (c *Controller) expire(ctx context.Context, now time.Time) {
	for id, l := range c.leases {
		if now.Before(l.expiresAt) {
			continue
		}
		r := l.rule
		delete(c.leases, id)
		c.send(ctx, bgp.Update{Session: c.session, Peer: c.peer, Op: bgp.OpWithdraw, Rule: &r})
		c.log.Info("local detector rule expired", "event", id)
	}
}

func (c *Controller) withdrawAll(ctx context.Context) {
	for id, l := range c.leases {
		r := l.rule
		delete(c.leases, id)
		c.send(ctx, bgp.Update{Session: c.session, Peer: c.peer, Op: bgp.OpWithdraw, Rule: &r})
	}
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
