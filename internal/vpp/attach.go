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
// direction (§16). It replaces each selected interface's ACL list with our
// Managed ACLs. For ingress, both ACLs are input ACLs (n_input = count).
//
// v1 owns the box (bump-in-the-wire, §16) and sets the interface ACL list
// outright; it does not merge with pre-existing ACLs.
func (c *Client) Attach(ctx context.Context) error {
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

	var nInput uint8
	if c.cfg.Direction == Ingress {
		nInput = uint8(len(acls))
	}

	for _, in := range ifs {
		_, err := c.aclc.ACLInterfaceSetACLList(ctx, &acl.ACLInterfaceSetACLList{
			SwIfIndex: in.index,
			Count:     uint8(len(acls)),
			NInput:    nInput,
			Acls:      acls,
		})
		if err != nil {
			return fmt.Errorf("acl_interface_set_acl_list on %s: %w", in.name, err)
		}
		c.log.Info("attached Managed ACLs to interface",
			"interface", in.name, "sw_if_index", in.index,
			"direction", directionString(c.cfg.Direction), "acls", acls)
	}
	return nil
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
