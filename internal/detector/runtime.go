package detector

import (
	"context"
	"log/slog"
	"time"
)

// Runner folds samples into the engine and periodically evaluates triggers,
// emitting events. Input/output channels are caller-owned so runtime wiring can
// choose bounded sizes.
type Runner struct {
	engine   *Engine
	samples  <-chan Sample
	events   chan<- Event
	ctx      EvalContext
	interval time.Duration
	log      *slog.Logger

	// snapshotReq carries on-demand /status snapshot requests onto the run loop, so
	// the expensive per-instance snapshot is built only when actually queried (not
	// every tick). done is closed when Run returns, so a request never blocks after
	// the runner stops.
	snapshotReq chan chan EngineSnapshot
	done        chan struct{}
}

func NewRunner(engine *Engine, samples <-chan Sample, events chan<- Event, logger *slog.Logger) *Runner {
	return NewRunnerWithContext(engine, samples, events, EvalContext{}, logger)
}

func NewRunnerWithContext(engine *Engine, samples <-chan Sample, events chan<- Event, eval EvalContext, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	interval := engine.TickInterval()
	if interval <= 0 {
		interval = time.Second
	}
	return &Runner{
		engine:      engine,
		samples:     samples,
		events:      events,
		ctx:         eval,
		interval:    interval,
		log:         logger,
		snapshotReq: make(chan chan EngineSnapshot),
		done:        make(chan struct{}),
	}
}

func (r *Runner) SetEvalContext(ctx EvalContext) {
	r.ctx = ctx
}

// Run folds samples until the context is cancelled. A ticker drives trigger
// evaluation off the sample hot path.
func (r *Runner) Run(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-r.samples:
			if !ok {
				return
			}
			r.engine.Observe(s)
		case now := <-ticker.C:
			events := r.engine.Tick(now, r.ctx)
			for _, ev := range events {
				select {
				case r.events <- ev:
				default:
					r.log.Debug("drop detector event: local rule queue full", "event", ev.ID)
				}
			}
		case reply := <-r.snapshotReq:
			reply <- r.engine.Snapshot(time.Now(), r.ctx)
		}
	}
}

// Snapshot returns a fresh point-in-time view of the engine for /status. It is
// built on the run goroutine on demand, so the per-instance snapshot cost is paid
// only when actually queried — not on every tick. Safe to call from any
// goroutine; returns an empty snapshot once the runner has stopped.
func (r *Runner) Snapshot() EngineSnapshot {
	reply := make(chan EngineSnapshot, 1)
	select {
	case r.snapshotReq <- reply:
		select {
		case snap := <-reply:
			return snap
		case <-r.done:
			return EngineSnapshot{}
		}
	case <-r.done:
		return EngineSnapshot{}
	}
}
