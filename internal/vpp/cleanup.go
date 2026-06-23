package vpp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.fd.io/govpp/binapi/acl"
)

// managedTag reports whether a VPP ACL tag is one this agent owns.
func (c *Client) managedTag(tag string) bool {
	tag = strings.TrimRight(tag, "\x00")
	return tag != "" && (tag == c.cfg.ACLTagV4 || tag == c.cfg.ACLTagV6)
}

// taggedACLs returns the indices of every VPP ACL carrying one of our tags.
func (c *Client) taggedACLs(ctx context.Context) ([]uint32, error) {
	stream, err := c.aclc.ACLDump(ctx, &acl.ACLDump{ACLIndex: aclIndexUnset})
	if err != nil {
		return nil, fmt.Errorf("acl_dump: %w", err)
	}
	var out []uint32
	for {
		d, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("acl_dump recv: %w", err)
		}
		if c.managedTag(d.Tag) {
			out = append(out, d.ACLIndex)
		}
	}
	return out, nil
}

// cleanupTaggedExcept deletes every ACL carrying one of our tags except those in
// keep (our freshly-created Managed ACLs). This removes orphans left by a prior
// run that exited without cleaning up, or by a VPP-side re-bootstrap. Best-effort:
// an ACL still attached somewhere fails to delete and is logged, not fatal.
func (c *Client) cleanupTaggedExcept(ctx context.Context, keep ...uint32) {
	kept := make(map[uint32]bool, len(keep))
	for _, k := range keep {
		kept[k] = true
	}
	indices, err := c.taggedACLs(ctx)
	if err != nil {
		c.log.Warn("acl cleanup: dump failed", "error", err)
		return
	}
	for _, i := range indices {
		if kept[i] {
			continue
		}
		if _, err := c.aclc.ACLDel(ctx, &acl.ACLDel{ACLIndex: i}); err != nil {
			c.log.Warn("acl cleanup: delete orphan failed (still attached?)", "acl_index", i, "error", err)
			continue
		}
		c.log.Info("acl cleanup: deleted orphaned managed ACL", "acl_index", i)
	}
}

// cleanupOnClose detaches our Managed ACLs from any interface that references
// them and deletes them, so a clean exit leaves no tagged ACLs behind. It only
// removes OUR indices — other ACLs on those interfaces are preserved. Best-effort:
// every step is logged on failure and the connection is closed regardless. Note
// that detaching briefly lifts the FlowSpec drops until the agent restarts.
func (c *Client) cleanupOnClose(ctx context.Context) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	c.mu.Lock()
	ours := make(map[uint32]bool, 2)
	var indices []uint32
	for _, f := range []Family{IPv4, IPv6} {
		if c.idx[f] != aclIndexUnset {
			ours[c.idx[f]] = true
			indices = append(indices, c.idx[f])
		}
	}
	c.mu.Unlock()
	if len(ours) == 0 {
		return
	}

	if err := c.detachManagedLocked(ctx, ours); err != nil {
		c.log.Warn("acl cleanup on exit: detach failed", "error", err)
	}
	for _, i := range indices {
		if _, err := c.aclc.ACLDel(ctx, &acl.ACLDel{ACLIndex: i}); err != nil {
			c.log.Warn("acl cleanup on exit: delete failed", "acl_index", i, "error", err)
			continue
		}
		c.log.Info("acl cleanup on exit: deleted managed ACL", "acl_index", i)
	}
}

// detachManagedLocked removes our ACL indices (ours) from every interface that
// references them, leaving any other ACLs — and their input/output split — intact.
// c.opMu must be held.
func (c *Client) detachManagedLocked(ctx context.Context, ours map[uint32]bool) error {
	lists, err := c.interfaceACLLists(ctx)
	if err != nil {
		return err
	}
	for idx, cur := range lists {
		hasOurs := false
		for _, a := range cur.acls {
			if ours[a] {
				hasOurs = true
				break
			}
		}
		if !hasOurs {
			continue // leave interfaces we don't touch alone
		}
		// Keep everything except ours; the kept input ACLs stay first so NInput is
		// just their count.
		in, out := splitNonManaged(cur.acls, cur.nInput, ours)
		kept := make([]uint32, 0, len(in)+len(out))
		kept = append(kept, in...)
		kept = append(kept, out...)
		if _, err := c.aclc.ACLInterfaceSetACLList(ctx, &acl.ACLInterfaceSetACLList{
			SwIfIndex: idx,
			Count:     uint8(len(kept)),
			NInput:    uint8(len(in)),
			Acls:      kept,
		}); err != nil {
			return fmt.Errorf("rewrite acl list on sw_if_index %d: %w", idx, err)
		}
	}
	return nil
}
