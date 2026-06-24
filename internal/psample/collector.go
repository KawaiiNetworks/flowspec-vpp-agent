// Package psample collects detector samples from the Linux kernel PSAMPLE generic
// netlink channel, which VPP's native sFlow plugin feeds. Compared with the
// sFlow-over-UDP collector it skips hsflowd and the UDP hop entirely: the agent
// subscribes to the PSAMPLE multicast group directly and decodes the sampled
// packet headers it carries (reusing internal/packet, the shared parsing layer).
package psample

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"

	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/detector"
	"github.com/kawaiinetworks/flowspec-vpp-agent/internal/packet"
)

const (
	familyName = "psample" // PSAMPLE_GENL_NAME
	groupName  = "packets" // PSAMPLE_NL_MCGRP_SAMPLE_NAME

	// PSAMPLE attribute types (uapi/linux/psample.h).
	attrIIFIndex    = 0
	attrSampleGroup = 3
	attrSampleRate  = 5
	attrData        = 6
)

// Collector subscribes to the PSAMPLE multicast group and emits detector samples.
// Its method set matches the sFlow collector (Listen/Run/Dropped) so the two are
// interchangeable behind a small interface in main.
type Collector struct {
	group   uint32 // only accept this PSAMPLE sample-group (0 = accept any)
	samples chan<- detector.Sample
	log     *slog.Logger

	conn    *genetlink.Conn
	groupID uint32
	dropped atomic.Int64
}

// New creates a PSAMPLE collector. group filters by PSAMPLE sample-group id (set
// it to the group VPP's sflow plugin uses; 0 accepts any).
func New(group uint32, samples chan<- detector.Sample, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		group:   group,
		samples: samples,
		log:     logger,
	}
}

// Dropped returns the cumulative number of samples dropped because the detector
// queue was full.
func (c *Collector) Dropped() int64 { return c.dropped.Load() }

// Listen dials generic netlink, resolves the psample family and joins its sample
// multicast group. It is separated from Run so startup failures (e.g. the kernel
// psample module not loaded) are reported synchronously by main.
func (c *Collector) Listen() error {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial generic netlink: %w", err)
	}
	family, err := conn.GetFamily(familyName)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("resolve psample genetlink family (is the kernel psample module loaded?): %w", err)
	}
	for _, g := range family.Groups {
		if g.Name == groupName {
			c.groupID = g.ID
			break
		}
	}
	if c.groupID == 0 {
		_ = conn.Close()
		return fmt.Errorf("psample multicast group %q not found", groupName)
	}
	if err := conn.JoinGroup(c.groupID); err != nil {
		_ = conn.Close()
		return fmt.Errorf("join psample group: %w", err)
	}
	c.conn = conn
	return nil
}

// Run receives PSAMPLE messages until ctx is cancelled. The samples channel is
// caller-owned and is not closed by Run.
func (c *Collector) Run(ctx context.Context) error {
	if c.conn == nil {
		if err := c.Listen(); err != nil {
			return err
		}
	}
	conn := c.conn
	defer conn.Close()
	// The watcher closes the conn on cancellation to unblock Receive; done makes it
	// exit if Run returns for any other reason, so it never leaks.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	c.log.Info("PSAMPLE collector listening", "group", c.group)
	for {
		msgs, _, err := conn.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.log.Warn("receive PSAMPLE", "error", err)
			continue
		}
		for _, m := range msgs {
			s, ok := c.decode(m, time.Now())
			if !ok {
				continue
			}
			select {
			case c.samples <- s:
			default:
				c.dropped.Add(1)
				c.log.Debug("drop PSAMPLE sample: detector queue full")
			}
		}
	}
}

// decode turns one PSAMPLE message into a detector sample, or returns false if it
// carries no packet data or does not match the configured sample group.
func (c *Collector) decode(m genetlink.Message, now time.Time) (detector.Sample, bool) {
	ad, err := netlink.NewAttributeDecoder(m.Data)
	if err != nil {
		return detector.Sample{}, false
	}
	var (
		data       []byte
		sampleRate uint32
		group      uint32
		ifindex    uint32
		haveGroup  bool
	)
	for ad.Next() {
		switch ad.Type() {
		case attrIIFIndex:
			ifindex = ad.Uint32() // PSAMPLE_ATTR_IIFINDEX is u32 (4 bytes)
		case attrSampleGroup:
			group = ad.Uint32()
			haveGroup = true
		case attrSampleRate:
			sampleRate = ad.Uint32()
		case attrData:
			data = ad.Bytes()
		}
	}
	if ad.Err() != nil || len(data) == 0 {
		return detector.Sample{}, false
	}
	if c.group != 0 && haveGroup && group != c.group {
		return detector.Sample{}, false
	}
	return packet.FromEthernet(data, now, sampleRate, ifname(ifindex))
}

// ifname renders the ingress ifindex as "ifindex:N" — the same form the sFlow
// path uses (internal/sflow ifIndexName) — so both sources match vppstats'
// per-interface ifindex alias (vppstats registers each interface under its VPP
// name plus an "ifindex:N" alias). Resolving to a Linux interface name instead
// would match neither the VPP name nor the alias.
func ifname(i uint32) string {
	if i == 0 {
		return ""
	}
	return fmt.Sprintf("ifindex:%d", i)
}
