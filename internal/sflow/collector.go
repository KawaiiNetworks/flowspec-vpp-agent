package sflow

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
)

// Collector receives sFlow datagrams and emits compact detector samples.
type Collector struct {
	listen  string
	pc      net.PacketConn
	samples chan<- detector.Sample
	log     *slog.Logger
	decoder Decoder
}

// NewCollector creates a UDP sFlow collector.
func NewCollector(listen string, samples chan<- detector.Sample, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		listen:  listen,
		samples: samples,
		log:     logger,
	}
}

// Listen binds the UDP socket. It is separated from Run so startup failures are
// reported synchronously by the main program.
func (c *Collector) Listen() error {
	pc, err := net.ListenPacket("udp", c.listen)
	if err != nil {
		return err
	}
	c.pc = pc
	return nil
}

// Run listens until ctx is cancelled. The samples channel is owned by the caller
// and is not closed by Run.
func (c *Collector) Run(ctx context.Context) error {
	if c.pc == nil {
		if err := c.Listen(); err != nil {
			return err
		}
	}
	pc := c.pc
	defer pc.Close()
	// The watcher closes the socket on cancellation to unblock ReadFrom; done
	// makes it exit if Run returns for any other reason, so it never leaks.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = pc.Close()
		case <-done:
		}
	}()

	buf := make([]byte, 65535)
	c.log.Info("sFlow collector listening", "addr", c.listen)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.log.Warn("read sFlow datagram", "error", err)
			continue
		}
		samples, err := c.decoder.Decode(buf[:n], time.Now())
		if err != nil {
			c.log.Debug("drop malformed sFlow datagram", "error", err)
			continue
		}
		for _, s := range samples {
			select {
			case c.samples <- s:
			default:
				c.log.Debug("drop sFlow sample: detector queue full")
			}
		}
	}
}
