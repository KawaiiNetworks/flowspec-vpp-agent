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
		engine:   engine,
		samples:  samples,
		events:   events,
		ctx:      eval,
		interval: interval,
		log:      logger,
	}
}

func (r *Runner) SetEvalContext(ctx EvalContext) {
	r.ctx = ctx
}

// Run folds samples until the context is cancelled. A ticker drives trigger
// evaluation off the sample hot path.
func (r *Runner) Run(ctx context.Context) {
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
			for _, ev := range r.engine.Tick(now, r.ctx) {
				select {
				case r.events <- ev:
				default:
					r.log.Debug("drop detector event: local rule queue full", "event", ev.ID)
				}
			}
		}
	}
}
