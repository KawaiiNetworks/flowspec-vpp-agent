package vpp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.fd.io/govpp/binapi/acl"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
)

// ifaceInfo is the subset of SwInterfaceDetails we care about.
type ifaceInfo struct {
	index interface_types.InterfaceIndex
	name  string
}

// Attach applies both Managed ACLs to the data-plane interfaces in the configured
// direction (§16). Our pair is placed LAST in that direction (input ACLs for
// ingress, output ACLs for egress): VPP matches a list in order, first match wins,
// so any manually-configured ACLs keep their precedence and ours act as the final
// policy — which is what an operator's explicit permit/deny should do. Pre-existing
// non-managed ACLs are preserved; only ACLs carrying our own tag are stripped (and
// our current pair re-appended in canonical position), so re-attach is idempotent.
func (c *Client) Attach(ctx context.Context) error {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	return c.attachLocked(ctx)
}

// attachLocked applies both Managed ACLs while c.opMu is held by the caller.
func (c *Client) attachLocked(ctx context.Context) error {
	acls := c.aclIndices()
	if len(acls) == 0 {
		return errors.New("no managed ACLs to attach")
	}

	ifs, err := c.dataPlaneInterfaces(ctx)
	if err != nil {
		return err
	}
	if len(ifs) == 0 {
		c.log.Warn("no data-plane interfaces found to attach Managed ACLs to")
		return nil
	}

	// Every ACL carrying our tag: our freshly-created pair plus any orphans from a
	// prior run. We strip all of them from an interface's list before re-appending
	// the current pair, so (a) re-attach never duplicates ours and (b) orphans get
	// detached here, letting cleanupTaggedExcept delete them afterwards.
	managed := make(map[uint32]bool, len(acls))
	if tagged, err := c.taggedACLs(ctx); err != nil {
		c.log.Warn("attach: tag dump failed, merging against current ACLs only", "error", err)
	} else {
		for _, i := range tagged {
			managed[i] = true
		}
	}
	for _, i := range acls {
		managed[i] = true
	}

	lists, err := c.interfaceACLLists(ctx)
	if err != nil {
		return err
	}

	for _, in := range ifs {
		cur := lists[in.index] // absent interface -> zero value: empty list
		newAcls, nInput := mergeManagedLast(cur.acls, cur.nInput, managed, acls, c.cfg.Direction)
		if _, err := c.aclc.ACLInterfaceSetACLList(ctx, &acl.ACLInterfaceSetACLList{
			SwIfIndex: in.index,
			Count:     uint8(len(newAcls)),
			NInput:    nInput,
			Acls:      newAcls,
		}); err != nil {
			return fmt.Errorf("acl_interface_set_acl_list on %s: %w", in.name, err)
		}
		c.log.Info("attached Managed ACLs to interface",
			"interface", in.name, "sw_if_index", in.index,
			"direction", directionString(c.cfg.Direction), "acls", acls, "list", newAcls)
	}
	return nil
}

// aclList is an interface's ACL configuration: the ordered ACL indices and how
// many leading entries are input ACLs (the remainder are output ACLs).
type aclList struct {
	acls   []uint32
	nInput uint8
}

// interfaceACLLists dumps every interface's current ACL list. Interfaces with no
// ACLs are absent from the map (callers treat that as the zero aclList).
func (c *Client) interfaceACLLists(ctx context.Context) (map[interface_types.InterfaceIndex]aclList, error) {
	stream, err := c.aclc.ACLInterfaceListDump(ctx, &acl.ACLInterfaceListDump{
		SwIfIndex: ^interface_types.InterfaceIndex(0), // all interfaces
	})
	if err != nil {
		return nil, fmt.Errorf("acl_interface_list_dump: %w", err)
	}
	out := map[interface_types.InterfaceIndex]aclList{}
	for {
		d, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("acl_interface_list_dump recv: %w", err)
		}
		acls := make([]uint32, len(d.Acls))
		copy(acls, d.Acls)
		out[d.SwIfIndex] = aclList{acls: acls, nInput: d.NInput}
	}
	return out, nil
}

// splitNonManaged partitions an interface's ACL list into its input and output
// ACLs (the first nInput entries are inputs), dropping every index in managed and
// preserving the order of the rest.
func splitNonManaged(cur []uint32, nInput uint8, managed map[uint32]bool) (in, out []uint32) {
	for i, a := range cur {
		if managed[a] {
			continue
		}
		if uint8(i) < nInput {
			in = append(in, a)
		} else {
			out = append(out, a)
		}
	}
	return in, out
}

// mergeManagedLast strips every managed ACL from cur, then appends ours at the END
// of the direction we manage (input for Ingress, output for Egress) so manual ACLs
// keep precedence. Returns the new list and its input count.
func mergeManagedLast(cur []uint32, nInput uint8, managed map[uint32]bool, ours []uint32, dir Direction) ([]uint32, uint8) {
	in, out := splitNonManaged(cur, nInput, managed)
	if dir == Ingress {
		in = append(in, ours...)
	} else {
		out = append(out, ours...)
	}
	merged := make([]uint32, 0, len(in)+len(out))
	merged = append(merged, in...)
	merged = append(merged, out...)
	return merged, uint8(len(in))
}

// dataPlaneInterfaces enumerates interfaces, applying the configured selection
// (§16): mode "all" returns every non-local interface; mode "list" returns only
// those whose name appears in InterfaceList.
func (c *Client) dataPlaneInterfaces(ctx context.Context) ([]ifaceInfo, error) {
	stream, err := c.ifc.SwInterfaceDump(ctx, &interfaces.SwInterfaceDump{
		SwIfIndex: ^interface_types.InterfaceIndex(0), // all
	})
	if err != nil {
		return nil, fmt.Errorf("sw_interface_dump: %w", err)
	}

	allow := map[string]bool{}
	if c.cfg.InterfaceMode == "list" {
		for _, n := range c.cfg.InterfaceList {
			allow[n] = true
		}
	}

	var out []ifaceInfo
	for {
		details, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("sw_interface_dump recv: %w", err)
		}
		name := strings.TrimRight(details.InterfaceName, "\x00")
		if details.SwIfIndex == 0 || strings.HasPrefix(name, "local") {
			continue // skip local0
		}
		if c.cfg.InterfaceMode == "list" && !allow[name] {
			continue
		}
		out = append(out, ifaceInfo{index: details.SwIfIndex, name: name})
	}
	return out, nil
}

func directionString(d Direction) string {
	if d == Egress {
		return "egress"
	}
	return "ingress"
}
