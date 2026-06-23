package vppstats

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"go.fd.io/govpp/adapter/statsclient"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/core"
)

type Options struct {
	Socket   string
	Interval time.Duration
}

type Poller struct {
	opts  Options
	store *Store
	log   *slog.Logger
}

func NewPoller(opts Options, store *Store, logger *slog.Logger) *Poller {
	if opts.Interval <= 0 {
		opts.Interval = time.Second
	}
	if store == nil {
		store = NewStore(DefaultRingConfig())
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Poller{opts: opts, store: store, log: logger}
}

func (p *Poller) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if p.runConnected(ctx) {
			return
		}
	}
}

func (p *Poller) runConnected(ctx context.Context) bool {
	client := statsclient.NewStatsClient(
		p.opts.Socket,
		statsclient.SetSocketRetryPeriod(time.Second),
		statsclient.SetSocketRetryTimeout(10*time.Second),
	)
	conn, err := core.ConnectStats(client)
	if err != nil {
		p.log.Warn("connect VPP stats", "socket", p.opts.Socket, "error", err)
		return sleepContext(ctx, p.opts.Interval)
	}
	defer conn.Disconnect()

	p.log.Info("VPP stats poller connected", "socket", p.opts.Socket, "interval", p.opts.Interval.String())
	ticker := time.NewTicker(p.opts.Interval)
	defer ticker.Stop()
	var prev map[string]counters
	for {
		select {
		case <-ctx.Done():
			return true
		case now := <-ticker.C:
			var stats api.InterfaceStats
			if err := conn.GetInterfaceStats(&stats); err != nil {
				p.log.Warn("read VPP interface stats", "error", err)
				return sleepContext(ctx, p.opts.Interval)
			}
			cur := snapshot(now, stats)
			if prev != nil {
				p.addRates(now, prev, cur)
			}
			prev = cur
		}
	}
}

func (p *Poller) addRates(now time.Time, prev, cur map[string]counters) {
	for name, c := range cur {
		old, ok := prev[name]
		if !ok || !c.at.After(old.at) {
			continue
		}
		seconds := c.at.Sub(old.at).Seconds()
		if seconds <= 0 {
			continue
		}
		p.store.Add(Sample{
			At:      now,
			Name:    name,
			RXPPS:   deltaRate(old.rxPackets, c.rxPackets, seconds),
			TXPPS:   deltaRate(old.txPackets, c.txPackets, seconds),
			DropPPS: deltaRate(old.drops, c.drops, seconds),
		})
	}
}

type counters struct {
	at        time.Time
	rxPackets uint64
	txPackets uint64
	drops     uint64
}

func snapshot(now time.Time, stats api.InterfaceStats) map[string]counters {
	out := make(map[string]counters, len(stats.Interfaces))
	for _, iface := range stats.Interfaces {
		c := counters{
			at:        now,
			rxPackets: iface.Rx.Packets,
			txPackets: iface.Tx.Packets,
			drops:     iface.Drops,
		}
		if iface.InterfaceName != "" {
			out[iface.InterfaceName] = c
		}
		out[stringIndex(iface.InterfaceIndex)] = c
	}
	return out
}

func deltaRate(old, cur uint64, seconds float64) float64 {
	if cur < old {
		return 0
	}
	return float64(cur-old) / seconds
}

func stringIndex(index uint32) string {
	return "ifindex:" + strconv.FormatUint(uint64(index), 10)
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}
