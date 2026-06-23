// Command flowspec-vpp-agent is the control-plane adapter that consumes BGP
// FlowSpec from multiple peers and programs the equivalent VPP ACLs (§18, §20).
//
// Assembly order (§20): read config -> start metrics/health HTTP -> connect VPP
// (with backoff) -> build manager -> start BGP -> pump updates -> handle signals.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/config"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/localrules"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/manager"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/metrics"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/sflow"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/version"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vpp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/vppstats"
)

const defaultConfigPath = "/etc/flowspec-vpp-agent/config.yaml"

func main() {
	// Subcommands: healthcheck (for the compose healthcheck), version.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(runHealthcheck(os.Args[2:]))
		case "version":
			fmt.Println(version.String())
			return
		}
	}

	cfgPath := flag.String("config", defaultConfigPath, "path to config.yaml")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Log)
	logger.Info("starting flowspec-vpp-agent", "version", version.String())

	if err := run(cfg, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Metrics collectors are always active internally; the HTTP endpoint is
	// opt-in, so default deployments do not expose an extra listener.
	reg := prometheus.NewRegistry()
	met := metrics.New(reg)
	httpSrv := startHTTP(cfg.Metrics.Listen, reg, logger)
	defer shutdownHTTP(httpSrv, logger)

	// Connect to VPP with backoff (§19.3: never crash on an unready socket).
	logger.Info("connecting to VPP", "socket", cfg.VPP.Socket)
	vppClient, err := vpp.Connect(ctx, vpp.ClientConfig{
		Socket:        cfg.VPP.Socket,
		InterfaceMode: cfg.Interfaces.Mode,
		InterfaceList: cfg.Interfaces.List,
		Direction:     direction(cfg.Interfaces.Direction),
	}, logger)
	if err != nil {
		return fmt.Errorf("connect VPP: %w", err)
	}
	defer vppClient.Close()

	mgr := manager.New(vppClient, met, logger)

	// Merge BGP updates with reconnect-driven resyncs onto a single channel so the
	// manager stays single-goroutine (§17).
	updates := make(chan bgp.Update, 2048)
	vppClient.OnReconnect = func() {
		select {
		case updates <- bgp.Update{Op: bgp.OpResync}:
		case <-ctx.Done():
		}
	}

	bgpSrv := bgp.New(toBGPOptions(cfg.BGP), logger)
	if err := bgpSrv.Start(ctx); err != nil {
		return fmt.Errorf("start BGP: %w", err)
	}
	defer bgpSrv.Stop()

	go func() {
		for u := range bgpSrv.Updates() {
			select {
			case updates <- u:
			case <-ctx.Done():
				return
			}
		}
	}()

	if cfg.Local.Enabled {
		rules, err := compileLocalRules(cfg.Local)
		if err != nil {
			return err
		}
		logLocalDetectorConfig(logger, cfg.Local, len(rules))

		samples := make(chan detector.Sample, cfg.Local.SampleQueue)
		events := make(chan detector.Event, cfg.Local.EventQueue)

		collector := sflow.NewCollector(cfg.Local.SFlow.Listen, samples, logger)
		if err := collector.Listen(); err != nil {
			return fmt.Errorf("listen sFlow: %w", err)
		}
		go func() {
			if err := collector.Run(ctx); err != nil {
				logger.Error("sFlow collector failed", "error", err)
				stop()
			}
		}()

		engine := detector.NewEngine(rules)
		logger.Info("local detector memory estimate",
			"rules", len(rules),
			"bytes", engine.MemoryEstimate(),
			"human", humanBytes(engine.MemoryEstimate()),
			"note", "upper bound at full max_instances")
		var statsView detector.StatsView
		if cfg.Local.VPPStats.Enabled {
			store := vppstats.NewStore(vppstats.DefaultRingConfig())
			statsView = store
			poller := vppstats.NewPoller(vppstats.Options{
				Socket:   cfg.VPP.StatsSocket,
				Interval: cfg.Local.VPPStats.Interval.Duration(),
			}, store, logger)
			go poller.Run(ctx)
		}
		go detector.NewRunnerWithContext(engine, samples, events, detector.EvalContext{Stats: statsView}, logger).Run(ctx)
		ctrl := localrules.New(updates, logger)
		ctrl.SetDryRun(cfg.Local.DryRun)
		if cfg.Local.DryRun {
			logger.Info("local detector in dry-run mode: events are logged, no ACLs are programmed")
		}
		go ctrl.Run(ctx, events)
	}

	logger.Info("agent running")
	mgr.Run(ctx, updates) // blocks until ctx is cancelled

	logger.Info("shutting down")
	return nil
}

func toBGPOptions(b config.BGP) bgp.Options {
	host, port := splitListen(b.Listen)
	peers := make([]bgp.PeerOptions, 0, len(b.Peers))
	for _, p := range b.Peers {
		peers = append(peers, bgp.PeerOptions{
			Address: p.Address, PeerASN: p.PeerASN, Port: p.Port, Passive: p.Passive,
		})
	}
	return bgp.Options{
		ASN:        b.ASN,
		RouterID:   b.RouterID,
		ListenAddr: host,
		ListenPort: int32(port),
		Peers:      peers,
	}
}

func direction(s string) vpp.Direction {
	if s == "egress" {
		return vpp.Egress
	}
	return vpp.Ingress
}

func splitListen(hp string) (host string, port int) {
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, 10179
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return host, 10179
	}
	return host, port
}

func newLogger(l config.Log) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(l.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.ToLower(l.Format) == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func startHTTP(addr string, reg *prometheus.Registry, logger *slog.Logger) *http.Server {
	if addr == "" {
		logger.Info("metrics/health endpoint disabled")
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics HTTP server failed", "error", err)
		}
	}()
	logger.Info("metrics/health endpoint listening", "addr", addr)
	return srv
}

func shutdownHTTP(srv *http.Server, logger *slog.Logger) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Warn("metrics HTTP shutdown", "error", err)
	}
}

// runHealthcheck implements the `healthcheck` subcommand used by the compose
// healthcheck (§19.1). When the optional HTTP endpoint is enabled, it GETs the
// local /healthz endpoint; when it is disabled, there is no listener to probe.
func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to config.yaml")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck config error:", err)
		return 1
	}
	addr := cfg.Metrics.Listen
	if addr == "" {
		return 0
	}
	// Connect to loopback regardless of the configured bind host.
	_, port := splitListen(addr)
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck failed:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck status:", resp.StatusCode)
		return 1
	}
	return 0
}
