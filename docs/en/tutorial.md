# Deployment & usage tutorial

> 🌐 **English** · [中文](../zh/tutorial.md)

This tutorial walks through getting `flowspec-vpp-agent` running: preparing VPP,
building the image, writing the config, announcing your first FlowSpec rule and
verifying it took effect. For per-field config details see
[configuration.md](configuration.md).

---

## 1. What it does

The agent is a **control-plane adapter**:

```
FlowSpec peer(s) ──BGP──▶ flowspec-vpp-agent ──VPP binary API──▶ VPP ACL
```

It consumes standard BGP FlowSpec (RFC 8955/8956) and translates the rules it can
map **equivalently** into VPP ACL `deny` entries, attached to all data-plane
interfaces on ingress. Rules it cannot express exactly are ignored (never
approximated) and surfaced as metrics so operators notice.

Key points:

- IPv4 / IPv6, announce and withdraw.
- Drop action only (`traffic-rate 0` / `discard`).
- Multi-session: rules from multiple peers are reference-counted into one pair of
  Managed ACLs (one IPv4, one IPv6); identical rules collapse to a single entry,
  removed only when the last holder withdraws.
- Depends only on the standard VPP ACL plugin; assumes no FastACL engine.

---

## 2. Prerequisites

- A host running **VPP** with the standard **ACL plugin** loaded, whose binary API
  socket is at `/run/vpp/api.sock` (owned by root or the vpp group).
- An **inline / bump-in-the-wire** deployment: traffic physically traverses VPP's
  data-plane interfaces, so attaching to all of them on ingress covers all traffic.
- One or more BGP peers that send FlowSpec (e.g. a FastNetMon FlowSpec exporter).
- A deployment method: docker / podman compose (recommended), or the raw binary.

---

## 3. Get the image / build

### 3.1 Published image

CI publishes to `kawaiinetworks/flowspec-vpp-agent`; compose references the `:main`
tag by default.

### 3.2 Build the binary locally

A static, CGO-free binary:

```sh
make build        # produces bin/flowspec-vpp-agent
make test         # unit + integration tests
```

> This repo is developed on NixOS; if `go` is not on PATH, use
> `nix-shell -p go --run 'make build'`.

### 3.3 Build the image locally

```sh
make docker       # builds kawaiinetworks/flowspec-vpp-agent:main
```

---

## 4. Write the config

Compose mounts the host's `./config` directory at `/etc/flowspec-vpp-agent`, and
the agent reads `config.yaml` inside it:

```sh
mkdir -p config
cp deploy/config.example.yaml config/config.yaml
```

Edit `config/config.yaml` as needed — most commonly `bgp.router_id`, `bgp.asn` and
`bgp.peers`:

```yaml
bgp:
  listen: "0.0.0.0:10179"     # default 10179, avoids a native BGP daemon
  router_id: "192.0.2.1"
  asn: 65000
  peers:
    - address: "198.51.100.1" # FlowSpec exporter
      peer_asn: 65001
      passive: true
```

Every field is explained in [configuration.md](configuration.md).

---

## 5. Deploy with compose

The deployment file is [../../deploy/compose.yaml](../../deploy/compose.yaml). Key
points:

- `volumes` mounts `/run/vpp` (covers both api.sock and stats.sock) and the
  `./config` directory.
- `network_mode: host`: the BGP listen port lands directly on the host; the socket
  still travels over the bind mount, so no container network is needed.
- `user: "0:0"`: run as root to access the root-owned api.sock.
- `healthcheck` runs `flowspec-vpp-agent healthcheck`; it is a no-op unless the
  optional metrics/health HTTP listener is enabled.

Start it:

```sh
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml logs -f
```

### podman + SELinux

Use `:z` (shared label) on the mount, **not `:Z`** (a private label would relabel
`/run/vpp` and may lock the host VPP out). More robustly, set
`security_opt: ["label=disable"]` on this container and leave `/run/vpp` untouched.
Under rootless podman the uid mapping makes socket access hard — prefer rootful /
root.

### Bridge networking (optional)

If you prefer not to use host networking, drop `network_mode: host` and publish the
port instead:

```yaml
ports:
  - "10179:10179"
```

The `/run/vpp` mount is unchanged.

---

## 6. Run the binary directly (no container)

```sh
sudo ./bin/flowspec-vpp-agent --config /path/to/config.yaml
```

The agent accesses the VPP socket as root and retries with backoff when the socket
is not ready or VPP restarts. Supervise it with any process manager (systemd,
supervisor, …) and enable automatic restart on failure.

---

## 7. Verify

### 7.1 Health and metrics

The metrics/health HTTP listener is disabled by default. Enable it explicitly if
you want local health and Prometheus scraping:

```yaml
metrics:
  listen: "127.0.0.1:9469"
```

```sh
curl -s http://127.0.0.1:9469/healthz          # should return ok
curl -s http://127.0.0.1:9469/metrics | grep flowspec_
```

Watch three metrics:

- `flowspec_rules_applied_total{family,peer}` — rules applied.
- `flowspec_rules_ignored_total{reason,family,peer}` — rules ignored (by
  reason/family/peer).
- `flowspec_acl_entries{family}` — current entry count per Managed ACL.

### 7.2 Inspect on the VPP side

```sh
vppctl show acl-plugin acl                      # Managed ACLs and their rules
vppctl show acl-plugin interface                # interface attachment (ingress)
```

After announcing "dst 203.0.113.10/32, udp, dport 443, traffic-rate 0", the IPv4
Managed ACL should contain one `deny` with dst `203.0.113.10/32`, proto 17, dst
port `443-443`, src `0.0.0.0/0`, src port `0-65535`. After withdraw the entry
disappears (unless another session still holds it).

---

## 8. Supported rule scope (quick reference)

**Supported match**: dst/src prefix, protocol/next-header (exact), dst/src port
(reducible to a single contiguous range, including `>`/`<`/`>=`/`<=`), tcp flags
(simple combinations like `syn`, `syn,!ack`), icmp type/code (exact).

**Rules that are ignored** (logged as warning + ignored metric, not programmed):

- Non-drop actions: `traffic-rate > 0`, redirect, marking, sample, etc.
- Port `!=`, disjoint port sets, complex OR expressions.
- Non-equality / multi-protocol OR for protocol.
- tcp flags on a non-TCP protocol; complex bitmasks (match any/none of).
- generic port, packet length, dscp, flow label.
- fragment (the standard ACL plugin has no matching field; the fragment condition
  cannot be dropped while programming the rest).
- IPv6 prefix `offset != 0` (no equivalent mapping).

See the metrics section of [configuration.md](configuration.md) for the full list.

---

## 9. Troubleshooting

| Symptom | Where to look |
| ------- | ------------- |
| Stuck at "connecting to VPP" after start | VPP not up or wrong `vpp.socket`; confirm `/run/vpp/api.sock` exists and is mounted. The agent does not crash — it keeps retrying. |
| Container cannot access the socket | Use `user: "0:0"`; for podman+SELinux use `:z` or `security_opt: label=disable`; avoid rootless. |
| Rules not taking effect | Check whether `flowspec_rules_ignored_total` is rising and read the `reason`/`detail` in `warn` logs; confirm the peer is `ESTABLISHED`. |
| Rules lost after VPP restart | The agent re-creates the Managed ACLs and re-pushes all rules (resync) after reconnect — no manual action needed. |
| Same rule from multiple sessions | Only one entry is created; it is retained as long as any session still holds it. |
