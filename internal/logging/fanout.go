package logging

import (
	"context"
	"log/slog"
)

// sink is one destination: an inner formatting handler gated by a minimum level
// and a scope filter. all==true accepts every scope; otherwise only scopes in the
// set are accepted.
type sink struct {
	level  slog.Level
	all    bool
	scopes map[string]bool
	h      slog.Handler
}

func (s sink) admits(level slog.Level, scope string) bool {
	if level < s.level {
		return false
	}
	return s.all || s.scopes[scope]
}

// fanout is a slog.Handler that forwards each record to every sink whose level
// and scope admit it. It tracks the record's scope as set by With(KeyScope, …):
// WithAttrs records the latest scope while still passing the attribute through to
// each inner handler so it renders in the output.
type fanout struct {
	sinks []sink
	scope string // current scope from With(KeyScope, …); "" => core
}

func newFanout(sinks []sink) *fanout { return &fanout{sinks: sinks} }

// Enabled reports whether any sink accepts this level. Scope is resolved per
// record in Handle, so Enabled gates on level only (never drops on scope).
func (f *fanout) Enabled(_ context.Context, level slog.Level) bool {
	for _, s := range f.sinks {
		if level >= s.level {
			return true
		}
	}
	return false
}

func (f *fanout) Handle(ctx context.Context, r slog.Record) error {
	scope := f.scope
	if scope == "" {
		scope = ScopeCore
	}
	// Allow a per-call scope override (rare; scopes are normally set via With).
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == KeyScope {
			scope = a.Value.String()
		}
		return true
	})
	for _, s := range f.sinks {
		if s.admits(r.Level, scope) {
			_ = s.h.Handle(ctx, r) // best-effort: one sink's failure must not stop others
		}
	}
	return nil
}

func (f *fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	scope := f.scope
	for _, a := range attrs {
		if a.Key == KeyScope {
			scope = a.Value.String()
		}
	}
	sinks := make([]sink, len(f.sinks))
	for i, s := range f.sinks {
		s.h = s.h.WithAttrs(attrs)
		sinks[i] = s
	}
	return &fanout{sinks: sinks, scope: scope}
}

func (f *fanout) WithGroup(name string) slog.Handler {
	sinks := make([]sink, len(f.sinks))
	for i, s := range f.sinks {
		s.h = s.h.WithGroup(name)
		sinks[i] = s
	}
	return &fanout{sinks: sinks, scope: f.scope}
}
