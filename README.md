# flowspec-vpp-agent

> 🌐 **English** · [中文](README.zh.md)

A control-plane adapter that consumes **BGP FlowSpec** (RFC 8955/8956) from one or
more peers and programs the equivalent **VPP ACLs** via the standard VPP ACL
plugin (`acl_add_replace`) over the GoVPP binary API.

It is a thin, conservative translator: it only programs rules that map
*equivalently* to a VPP ACL entry. Anything it cannot represent exactly is
ignored (never approximated) and surfaced as a Prometheus metric so an operator
can tell that a rule was dropped — for a DDoS-mitigation tool, a silently dropped
rule means an unmitigated attack.

Detailed docs: [deployment & usage tutorial](docs/en/tutorial.md) and
[configuration reference](docs/en/configuration.md).

## What it does

- **Address families:** IPv4 and IPv6 FlowSpec, announce and withdraw.
- **Match components:** dst/src prefix, protocol/next-header, dst/src port,
  TCP flags, ICMP type/code. Each must reduce to a single exact value or a single
  contiguous range — `!=`, disjoint OR sets, ranges where VPP expects an exact
  value, IPv6 prefix `offset != 0`, fragment, generic port, packet-length, DSCP
  and flow-label are all rejected.
- **Action:** drop only (`traffic-rate 0` / `discard`) → VPP `deny`. Rate-limit,
  redirect, marking, sample, etc. are ignored.
- **Multi-session:** multiple BGP peers are reference-counted into the same pair
  of Managed ACLs (one IPv4, one IPv6). Identical rules from different sessions
  collapse to one ACL entry; an entry is removed only when its last holder
  withdraws; a session going down withdraws all of its rules.
- **Application:** both Managed ACLs are attached to all data-plane interfaces in
  the ingress direction by default; configurable.
- **Observability:** `flowspec_rules_ignored_total{reason,family,peer}`,
  `flowspec_rules_applied_total{family,peer}`, `flowspec_acl_entries{family}`.

## Architecture

```
bgp (multi-session, GoBGP) ──Update{session,op,rule}──▶ manager
  manager: translate → ok ? refcount + reconcile : ignored(metric + log)
  vpp: acl_add_replace / attach Managed ACLs to all data-plane ifaces (ingress)
```

| Package            | Responsibility                                                        |
| ------------------ | --------------------------------------------------------------------- |
| `internal/flowspec`| Internal FlowSpec model + GoBGP NLRI/attr parsing.                    |
| `internal/translate`| Pure, stateless `Rule → vpp.ACLRule`; all support checks; densest tests. |
| `internal/manager` | The only stateful component: per-rule reference counts + reconcile.   |
| `internal/vpp`     | GoVPP backend: connect+backoff, `acl_add_replace`, interface attach.  |
| `internal/bgp`     | Embedded GoBGP speaker; emits source-agnostic `Update` events.        |
| `internal/config`  | YAML config + validation.                                             |
| `internal/metrics` | Prometheus collectors.                                                |

The VPP ACL/interface binary-API bindings come directly from the
`go.fd.io/govpp` module (which ships generated bindings), so there is no
`binapi/` generation step in this repository.

## Build & test

```sh
make build       # static binary -> bin/flowspec-vpp-agent
make test        # unit + integration tests
make vet
```

## Run

See [deploy/](deploy/): `compose.yaml`, `config.example.yaml`, `Dockerfile`.
The compose file mounts a `./config` directory (read-only) to
`/etc/flowspec-vpp-agent`, and the agent reads `config.yaml` inside it. Quick start:

```sh
mkdir -p config
cp deploy/config.example.yaml config/config.yaml   # edit peers / router_id
docker compose -f deploy/compose.yaml up -d
```

VPP must own `/run/vpp/api.sock`; the agent retries the socket with backoff and
does not crash if VPP is not yet ready or restarts.
