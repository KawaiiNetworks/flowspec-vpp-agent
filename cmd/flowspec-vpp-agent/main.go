// Command flowspec-vpp-agent is the control-plane adapter that consumes BGP
// FlowSpec from multiple peers and programs the equivalent VPP ACLs (§18, §20).
//
// Assembly order (§20): read config -> start metrics/health HTTP -> connect VPP
// (with backoff) -> build manager -> start BGP -> pump updates -> handle signals.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/bgp"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/config"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/localrules"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/logging"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/manager"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/metrics"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/psample"
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

	cfgPath := pflag.StringP("config", "c", defaultConfigPath, "path to config.yaml")
	pflag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	logger, logCloser := logging.New(cfg.Log.Options())
	clog := logger.With(logging.KeyScope, logging.ScopeCore)
	clog.Info("starting flowspec-vpp-agent", "version", version.String())

	err = run(cfg, logger)
	if err != nil {
		clog.Error("fatal", "error", err)
	}
	// Flush the Telegram sink on every exit path — after the fatal log is enqueued,
	// before os.Exit (which would skip a deferred close).
	_ = logCloser.Close()
	if err != nil {
		os.Exit(1)
	}
}

func run(cfg config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// clog carries the "core" scope for the agent's own lifecycle messages; each
	// subsystem below gets its own scope so sinks can filter by category.
	clog := logger.With(logging.KeyScope, logging.ScopeCore)

	// Metrics collectors are always active internally; the HTTP endpoint is
	// opt-in, so default deployments do not expose an extra listener.
	reg := prometheus.NewRegistry()
	met := metrics.New(reg)
	status := &statusProvider{started: time.Now()}
	httpSrv := startHTTP(cfg.Metrics.Listen, reg, status, clog)
	defer shutdownHTTP(httpSrv, clog)

	// Connect to VPP with backoff (§19.3: never crash on an unready socket).
	clog.Info("connecting to VPP", "socket", cfg.VPP.Socket)
	vppClient, err := vpp.Connect(ctx, vpp.ClientConfig{
		Socket:        cfg.VPP.Socket,
		InterfaceMode: cfg.ACL.Interfaces.Mode,
		InterfaceList: cfg.ACL.Interfaces.List,
		Direction:     direction(cfg.ACL.Interfaces.Direction),
	}, logger.With(logging.KeyScope, logging.ScopeVPP))
	if err != nil {
		return fmt.Errorf("connect VPP: %w", err)
	}
	defer vppClient.Close()

	mgr := manager.New(vppClient, met, logger.With(logging.KeyScope, logging.ScopeACL))

	// Merge BGP updates with reconnect-driven resyncs onto a single channel so the
	// manager stays single-goroutine (§17).
	updates := make(chan bgp.Update, 2048)
	vppClient.OnReconnect = func() {
		select {
		case updates <- bgp.Update{Op: bgp.OpResync}:
		case <-ctx.Done():
		}
	}

	// BGP is optional: it runs only when peers are configured. A detector-only
	// deployment programs VPP directly through the same updates channel.
	var bgpSrv *bgp.Server
	if cfg.BGPEnabled() {
		bgpSrv = bgp.New(toBGPOptions(cfg.BGP), logger.With(logging.KeyScope, logging.ScopeBGP))
		if err := bgpSrv.Start(ctx); err != nil {
			return fmt.Errorf("start BGP: %w", err)
		}
		defer bgpSrv.Stop()

		// bgpSrv.Updates() is never closed; this forwarder stops on ctx instead.
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case u := <-bgpSrv.Updates():
					select {
					case updates <- u:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	} else {
		clog.Info("BGP disabled (no peers configured)")
	}

	// onShutdown runs after the manager loop returns (and the detector runner has
	// stopped) to persist state, when configured.
	var onShutdown func()

	if cfg.DetectorEnabled() {
		det := cfg.Detector
		dlog := logger.With(logging.KeyScope, logging.ScopeDetector)
		rules, err := compileDetectorRules(det)
		if err != nil {
			return err
		}
		logDetectorConfig(clog, det, len(rules))

		samples := make(chan detector.Sample, det.SampleQueue)
		events := make(chan detector.Event, det.EventQueue)

		// Exactly one sample source is configured (enforced by Validate).
		var src sampleSource
		switch det.CollectorMode() {
		case "psample":
			src = psample.New(det.Collector.PSample.Group, samples, dlog)
		default: // "sflow"
			src = sflow.NewCollector(det.Collector.SFlow.Listen, samples, dlog)
		}
		if err := src.Listen(); err != nil {
			return fmt.Errorf("listen %s collector: %w", det.CollectorMode(), err)
		}
		status.setCollector(src)
		reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name:        "detector_samples_dropped_total",
			Help:        "Samples dropped because the detector sample queue was full.",
			ConstLabels: prometheus.Labels{"source": det.CollectorMode()},
		}, func() float64 { return float64(src.Dropped()) }))
		go func() {
			if err := src.Run(ctx); err != nil {
				dlog.Error("sample collector failed", "error", err)
				stop()
			}
		}()

		engine := detector.NewEngine(rules)
		clog.Info("detector memory estimate",
			"rules", len(rules),
			"bytes", engine.MemoryEstimate(),
			"human", humanBytes(engine.MemoryEstimate()),
			"note", "upper bound at full max_instances")
		var statsView detector.StatsView
		var statsStore *vppstats.Store
		if det.VPPStatsEnabled() {
			statsStore = vppstats.NewStore(vppRingConfig(det.VPPStats))
			statsView = statsStore
			status.setStats(statsStore)
			poller := vppstats.NewPoller(vppstats.Options{
				Socket:   cfg.VPP.StatsSocket,
				Interval: det.VPPStats.Interval.Duration(),
			}, statsStore, dlog)
			go poller.Run(ctx)
		}

		// Reload persisted history before the engine starts observing. Missing
		// rules, changed rule definitions, and changed ring shapes are skipped by
		// Import. Persist defaults to persist.dump next to the config (see config.Load).
		if cfg.Persist != "" {
			if st, err := loadState(cfg.Persist); err != nil {
				if !os.IsNotExist(err) {
					clog.Warn("load detector state", "file", cfg.Persist, "error", err)
				}
			} else {
				engine.Import(st.Detector)
				if statsStore != nil {
					statsStore.Import(st.VPP)
				}
				clog.Info("loaded persisted detector state", "file", cfg.Persist)
			}
		}

		runner := detector.NewRunnerWithContext(engine, samples, events, detector.EvalContext{Stats: statsView}, dlog)
		status.setRunner(runner)
		reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "detector_events_dropped_total",
			Help: "Detector events dropped because the local-rule queue was full.",
		}, func() float64 { return float64(runner.DroppedEvents()) }))
		runnerDone := make(chan struct{})
		go func() {
			runner.Run(ctx)
			close(runnerDone)
		}()

		if cfg.Persist != "" {
			onShutdown = func() {
				<-runnerDone // engine no longer mutated; safe to export
				st := agentState{Detector: engine.Export()}
				if statsStore != nil {
					st.VPP = statsStore.Export()
				}
				if err := saveState(cfg.Persist, st); err != nil {
					clog.Warn("save detector state", "file", cfg.Persist, "error", err)
				} else {
					clog.Info("saved detector state", "file", cfg.Persist)
				}
			}
		}
		ctrl := localrules.New(updates, dlog)
		ctrl.SetDryRun(det.DryRun)
		// Originate detector leases upstream when any peer is configured to receive
		// our FlowSpec (the BGP export policy restricts delivery to those peers).
		if bgpSrv != nil && hasSendPeer(cfg.BGP) {
			ctrl.SetAdvertiser(bgpSrv)
			clog.Info("detector leases will be advertised to send peers")
		}
		status.setLeases(ctrl)
		if cfg.Detector.DryRun {
			clog.Info("detector in dry-run mode: events are logged, no ACLs are programmed")
		}
		go ctrl.Run(ctx, events)
	}

	clog.Info("agent running")
	mgr.Run(ctx, updates) // blocks until ctx is cancelled

	clog.Info("shutting down")
	if onShutdown != nil {
		onShutdown()
	}
	return nil
}

func toBGPOptions(b config.BGP) bgp.Options {
	host, port := splitListen(b.Listen)
	peers := make([]bgp.PeerOptions, 0, len(b.Peers))
	for _, p := range b.Peers {
		peers = append(peers, bgp.PeerOptions{
			Address: p.Address, PeerASN: p.PeerASN, Port: p.Port, Passive: p.Passive,
			Receive: p.Receives(), Send: p.Send,
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

func hasSendPeer(b config.BGP) bool {
	for _, p := range b.Peers {
		if p.Send {
			return true
		}
	}
	return false
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

func startHTTP(addr string, reg *prometheus.Registry, status *statusProvider, logger *slog.Logger) *http.Server {
	if addr == "" {
		logger.Info("metrics/health endpoint disabled")
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/status", status.handler)
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
	fs := pflag.NewFlagSet("healthcheck", pflag.ContinueOnError)
	cfgPath := fs.StringP("config", "c", defaultConfigPath, "path to config.yaml")
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
