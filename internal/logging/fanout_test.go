package logging

import (
	"context"
	"log/slog"
	"sync"
	"testing"
)

// capture is an inner handler that counts the records routed to it.
type capture struct {
	mu    sync.Mutex
	count int
	last  string
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	c.last = r.Message
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func (c *capture) n() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// A record must reach every sink whose level AND scope admit it, and no others.
func TestFanout_Routing(t *testing.T) {
	all := &capture{}     // info, all scopes
	detACL := &capture{}  // info, {detector, acl}
	warnAll := &capture{} // warn, all scopes
	none := &capture{}    // info, empty scope set => disabled

	f := newFanout([]sink{
		{level: slog.LevelInfo, all: true, h: all},
		{level: slog.LevelInfo, scopes: map[string]bool{ScopeDetector: true, ScopeACL: true}, h: detACL},
		{level: slog.LevelWarn, all: true, h: warnAll},
		{level: slog.LevelInfo, scopes: nil, h: none},
	})
	lg := slog.New(f)

	cases := []struct {
		scope           string
		level           slog.Level
		wantAll, wantDA bool
		wantWarn        bool
	}{
		{ScopeDetector, slog.LevelInfo, true, true, false},
		{ScopeACL, slog.LevelInfo, true, true, false},
		{ScopeBGP, slog.LevelInfo, true, false, false},
		{ScopeACL, slog.LevelWarn, true, true, true},
		{ScopeVPP, slog.LevelError, true, false, true},
	}
	wantAll, wantDA, wantWarn := 0, 0, 0
	for _, tc := range cases {
		l := lg.With(KeyScope, tc.scope)
		l.Log(context.Background(), tc.level, "msg")
		if tc.wantAll {
			wantAll++
		}
		if tc.wantDA {
			wantDA++
		}
		if tc.wantWarn {
			wantWarn++
		}
	}

	if all.n() != wantAll {
		t.Errorf("all sink got %d, want %d", all.n(), wantAll)
	}
	if detACL.n() != wantDA {
		t.Errorf("[detector,acl] sink got %d, want %d", detACL.n(), wantDA)
	}
	if warnAll.n() != wantWarn {
		t.Errorf("warn sink got %d, want %d", warnAll.n(), wantWarn)
	}
	if none.n() != 0 {
		t.Errorf("empty-scope (none) sink got %d, want 0", none.n())
	}
}

// A record with no scope attribute is treated as core.
func TestFanout_MissingScopeIsCore(t *testing.T) {
	core := &capture{}
	other := &capture{}
	f := newFanout([]sink{
		{level: slog.LevelInfo, scopes: map[string]bool{ScopeCore: true}, h: core},
		{level: slog.LevelInfo, scopes: map[string]bool{ScopeBGP: true}, h: other},
	})
	slog.New(f).Info("unscoped")

	if core.n() != 1 {
		t.Errorf("core sink got %d, want 1 (unscoped => core)", core.n())
	}
	if other.n() != 0 {
		t.Errorf("bgp sink got %d, want 0", other.n())
	}
}
