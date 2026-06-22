package vpp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	govppcore "go.fd.io/govpp/core"

	"go.fd.io/govpp/adapter/socketclient"
	"go.fd.io/govpp/binapi/acl"
	interfaces "go.fd.io/govpp/binapi/interface"
)

// aclIndexUnset marks a Managed ACL whose VPP index is not yet known; passing it
// as acl_index to acl_add_replace asks VPP to create a new ACL.
const aclIndexUnset = ^uint32(0)

// reconnect retry tuning (§19.3: never crash on a missing/unready socket).
const (
	connectAttempts = 1 << 30 // effectively unlimited
	connectInterval = 2 * time.Second
)

// ClientConfig configures the GoVPP backend.
type ClientConfig struct {
	Socket        string
	InterfaceMode string // "all" or "list"
	InterfaceList []string
	Direction     Direction
	ACLTagV4      string
	ACLTagV6      string
}

// Client is the GoVPP-backed VPP Backend. It owns the connection (with backoff
// reconnect), the two Managed ACL indices, and interface attachment. It is the
// only place that speaks GoVPP (§18, §20).
type Client struct {
	cfg  ClientConfig
	log  *slog.Logger
	conn *govppcore.Connection
	aclc acl.RPCService
	ifc  interfaces.RPCService

	// OnReconnect, if set, is invoked after the Managed ACLs have been
	// re-created and re-attached following a VPP reconnect, so the manager can
	// re-push desired state (§19.3).
	OnReconnect func()

	mu  sync.Mutex
	idx map[Family]uint32
}

// Connect dials the VPP API socket, blocking with backoff until VPP is reachable
// or ctx is cancelled, then creates the Managed ACLs and attaches them to the
// data-plane interfaces (§16). It starts a background goroutine that handles
// subsequent disconnect/reconnect events.
func Connect(ctx context.Context, cfg ClientConfig, log *slog.Logger) (*Client, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.ACLTagV4 == "" {
		cfg.ACLTagV4 = "flowspec-managed-ip4"
	}
	if cfg.ACLTagV6 == "" {
		cfg.ACLTagV6 = "flowspec-managed-ip6"
	}

	adapter := socketclient.NewVppClient(cfg.Socket)
	conn, evCh, err := govppcore.AsyncConnect(adapter, connectAttempts, connectInterval)
	if err != nil {
		return nil, fmt.Errorf("vpp connect: %w", err)
	}

	c := &Client{
		cfg:  cfg,
		log:  log,
		conn: conn,
		idx:  map[Family]uint32{IPv4: aclIndexUnset, IPv6: aclIndexUnset},
	}

	if err := c.waitConnected(ctx, evCh); err != nil {
		conn.Disconnect()
		return nil, err
	}
	c.aclc = acl.NewServiceClient(conn)
	c.ifc = interfaces.NewServiceClient(conn)

	if err := c.bootstrap(ctx); err != nil {
		conn.Disconnect()
		return nil, err
	}

	go c.handleEvents(ctx, evCh)
	return c, nil
}

// waitConnected blocks until the first Connected event (or ctx cancellation).
func (c *Client) waitConnected(ctx context.Context, evCh chan govppcore.ConnectionEvent) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-evCh:
			if !ok {
				return fmt.Errorf("vpp connection closed before ready")
			}
			switch e.State {
			case govppcore.Connected:
				c.log.Info("connected to VPP", "socket", c.cfg.Socket)
				return nil
			case govppcore.Failed:
				c.log.Warn("vpp connect attempt failed, retrying", "error", e.Error)
			default:
				// keep waiting
			}
		}
	}
}

// bootstrap creates the (empty) Managed ACLs and attaches them to interfaces.
func (c *Client) bootstrap(ctx context.Context) error {
	if err := c.ReplaceACL(ctx, IPv4, nil); err != nil {
		return fmt.Errorf("create ipv4 managed acl: %w", err)
	}
	if err := c.ReplaceACL(ctx, IPv6, nil); err != nil {
		return fmt.Errorf("create ipv6 managed acl: %w", err)
	}
	if err := c.Attach(ctx); err != nil {
		return fmt.Errorf("attach managed acls: %w", err)
	}
	return nil
}

// handleEvents reacts to connection state changes for the life of the client.
// On reconnect it re-creates and re-attaches the Managed ACLs (their VPP indices
// are assumed lost) and triggers a resync so the manager re-pushes all rules.
func (c *Client) handleEvents(ctx context.Context, evCh chan govppcore.ConnectionEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-evCh:
			if !ok {
				return
			}
			switch e.State {
			case govppcore.Connected:
				c.log.Warn("reconnected to VPP, re-creating managed ACLs")
				c.mu.Lock()
				c.idx[IPv4] = aclIndexUnset
				c.idx[IPv6] = aclIndexUnset
				c.mu.Unlock()
				if err := c.bootstrap(ctx); err != nil {
					c.log.Error("re-bootstrap after reconnect failed", "error", err)
					continue
				}
				if c.OnReconnect != nil {
					c.OnReconnect()
				}
			case govppcore.Disconnected:
				c.log.Warn("disconnected from VPP, awaiting reconnect")
			case govppcore.Failed:
				c.log.Error("vpp reconnect failed", "error", e.Error)
			}
		}
	}
}

// Close releases the VPP connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Disconnect()
	}
}
