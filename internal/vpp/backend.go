package vpp

import "context"

// Family selects which Managed ACL a set of rules belongs to (§1). IPv4 rules
// only ever enter the IPv4 ACL and IPv6 rules the IPv6 ACL.
type Family uint8

const (
	IPv4 Family = iota
	IPv6
)

func (f Family) String() string {
	if f == IPv6 {
		return "ipv6"
	}
	return "ipv4"
}

// Direction is the ACL application direction. v1 fixes this to Ingress (§16).
type Direction uint8

const (
	Ingress Direction = iota
	Egress
)

// Backend is the seam between the manager (which owns desired state) and VPP
// (which owns reality). The manager only ever asks the backend to make a Managed
// ACL equal to a desired rule set; it never speaks GoVPP directly. Attaching the
// ACLs to interfaces (§16) is a startup concern handled by the concrete client,
// not part of this interface. Swapping the data-plane engine (e.g. a future
// FastACL backend, §18) means reimplementing only this interface.
//
// Implementations must be safe for use from a single manager goroutine.
type Backend interface {
	// ReplaceACL makes the Managed ACL for family hold exactly rules, in order,
	// via a single acl_add_replace. Creating the ACL on first use is the
	// implementation's responsibility.
	ReplaceACL(ctx context.Context, family Family, rules []ACLRule) error

	// Close releases the VPP connection.
	Close()
}
