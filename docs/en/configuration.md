# Configuration reference

> 🌐 **English** · [中文](../zh/configuration.md)

The agent is started with a single YAML config file, default path
`/etc/flowspec-vpp-agent/config.yaml` (override with `-config`). In the compose
deployment the host's `./config` directory is mounted read-only at
`/etc/flowspec-vpp-agent`, and the agent reads `config.yaml` inside it.

Each section is documented below. A complete example lives in
[../../deploy/config.example.yaml](../../deploy/config.example.yaml).

> Fields with a listed default may be omitted; required fields are called out
> below. The config is validated at startup; an invalid value makes the process
> exit non-zero and print the reason.

---

## vpp

VPP connection settings.

```yaml
vpp:
  socket: /run/vpp/api.sock
  stats_socket: /run/vpp/stats.sock
```

| Field          | Type   | Default                 | Description |
| -------------- | ------ | ----------------------- | ----------- |
| `socket`       | string | `/run/vpp/api.sock`     | VPP **binary API** unix socket. The agent uses it to issue `acl_add_replace`, enumerate interfaces and attach ACLs. **Required** (must be non-empty). |
| `stats_socket` | string | `/run/vpp/stats.sock`   | VPP stats socket path. Used when a `detector.vpp_stats` block is present. |

> Socket access from a container: `/run/vpp` is usually owned by root (or the vpp
> group); `user: "0:0"` in compose is the simplest. The agent retries with backoff
> when the socket is not ready or VPP restarts — it never crashes on startup.

---

## bgp

The embedded GoBGP speaker. Each peer is one FlowSpec session.

```yaml
bgp:
  listen: "0.0.0.0:10179"
  router_id: "192.0.2.1"
  asn: 65000
  peers:
    - address: "198.51.100.1"
      peer_asn: 65001
      passive: true
```

| Field       | Type   | Default          | Description |
| ----------- | ------ | ---------------- | ----------- |
| `listen`    | string | `0.0.0.0:10179`  | BGP listen `host:port`. **Defaults to 10179, not 179**, to avoid a native BGP daemon already bound to 179. Must be a valid `host:port`, port 1–65535. |
| `router_id` | string | —                | BGP Router ID in dotted-quad (IPv4) form. **Required**; GoBGP rejects an empty router ID. |
| `asn`       | uint32 | `0`              | Local AS number. |
| `peers`     | list   | empty            | FlowSpec sessions (see below). Multiple are allowed; their rules are reference-counted into the shared Managed ACLs. |

### bgp.peers[]

| Field      | Type   | Default | Description |
| ---------- | ------ | ------- | ----------- |
| `address`  | string | —       | Neighbor IP address. **Required and must be valid.** |
| `peer_asn` | uint32 | —       | Neighbor AS number. **Required and non-zero.** |
| `port`     | uint16 | `0`     | Neighbor TCP transport port; `0` means default. FlowSpec collectors (e.g. FastNetMon) usually dial in, so this is rarely needed. |
| `passive`  | bool   | `false` | Passive (listen-only) mode. Often `true` for FlowSpec collection. |
| `receive`  | bool   | `true`  | Import this peer's FlowSpec: apply it to VPP and relay it to `send` peers. Set `false` for an upstream you only advertise to. |
| `send`     | bool   | `false` | Advertise our entire FlowSpec table — both rules received from `receive` peers and detector-originated drops — to this peer. |

A peer must have `receive` or `send` (or both); `receive: false` together with
`send: false` is rejected. Each session negotiates both IPv4 and IPv6 FlowSpec
address families.

**Direction is enforced by GoBGP policy.** An export policy (default reject)
admits originated/relayed FlowSpec only to `send` peers, so a non-send peer never
receives our routes even though it negotiated the family. An import policy
(default reject) keeps a non-`receive` peer's routes out of the local RIB so they
are never relayed; inbound application to VPP is gated independently per peer.

The agent only ever **originates** a pure drop (`traffic-rate 0`). Relayed routes
are forwarded as received.

---

## acl

How the Managed ACLs are applied to the data plane. FlowSpec carries no
interface information, so this is purely local policy.

```yaml
acl:
  interfaces:
    mode: all
    direction: ingress
    # list:
    #   - GigabitEthernet0/0/0
```

### acl.interfaces

Where the Managed ACLs are applied, and in which direction.

| Field       | Type   | Default    | Description |
| ----------- | ------ | ---------- | ----------- |
| `mode`      | string | `all`      | `all` = every data-plane interface (auto-excludes `local0` and the like); `list` = only those named in `list`. Any other value is invalid. |
| `list`      | list   | empty      | **Required and non-empty when `mode: list`**; elements are VPP interface names (e.g. `GigabitEthernet0/0/0`). Ignored when `mode: all`. |
| `direction` | string | `ingress`  | ACL direction, `ingress` or `egress`. In a bump-in-the-wire deployment, ingress on all interfaces already covers all inbound traffic. |

---

## metrics

The Prometheus metrics and health-check HTTP endpoint.

```yaml
metrics:
  listen: ""
```

| Field    | Type   | Default      | Description |
| -------- | ------ | ------------ | ----------- |
| `listen` | string | empty string | Empty disables the HTTP listener. Set a valid `host:port` such as `127.0.0.1:9469` or `0.0.0.0:9469` to expose `/metrics`, `/healthz` and `/status`; the `healthcheck` subcommand requests `/healthz` on that port locally. |

Exposed metrics:

- `flowspec_rules_ignored_total{reason,family,peer}` — rules ignored because they
  cannot be equivalently mapped. `reason` distinguishes at least
  `unsupported_component` / `unsupported_expression` / `unsupported_action` /
  `unmappable_prefix`. **Alert on the rate of this metric**: a silently dropped
  rule means an unmitigated attack.
- `flowspec_rules_applied_total{family,peer}` — rules accepted and applied.
- `flowspec_acl_entries{family}` — current entry count of each Managed ACL (gauge).

### `/status` (JSON)

A `GET /status` on the same listener returns a JSON snapshot of the detector's
live state (empty sections when the detector is disabled):

- `traffic` — latest per-interface rates from the VPP stats poller
  (`rx_pps` / `tx_pps` / `rx_bps` / `tx_bps` / `sw_drop_pps` / `hw_drop_pps`).
- `rules` — every detector rule with its occupancy (`instance_count` /
  `max_instances`) and current instances. Each instance carries its descriptor
  (family, proto, src/dst, ports), current `pps` / `bps` from the fine ring, the
  evaluated trigger `terms`, and `firing` (whether the trigger expression is
  currently holding).
- `active` — the synthetic FlowSpec leases currently announced through the
  manager, each with its `flowspec` identity, `family` and `expires_at`.

The rule and lease sections refresh once per detector tick; traffic is the most
recent poll. The endpoint is read-only and unauthenticated — bind `listen` to a
trusted address.

---

## detector

Optional sFlow/VPP-stats detector. It listens for sFlow v5 datagrams,
updates fixed-capacity rule state, emits synthetic FlowSpec rules into the same
manager path as BGP, refreshes active leases, and withdraws them when TTL expires.

**The detector is enabled by the presence of a `detector:` section** — there is
no `enabled` flag. Likewise `vpp_stats` is enabled by the presence of a
`vpp_stats:` block. Omit the section to disable.

```yaml
detector:
  rules_dir: /etc/flowspec-vpp-agent/rules
  rules_enabled:
    - dns-reflection
    - udp-flood-ipv4
    - syn-flood-ipv4
    - ssh-scan-ipv4
  sflow:
    listen: "0.0.0.0:6343"
  sample_queue: 65536
  event_queue: 1024
  vpp_stats:       # presence enables counter polling; omit to disable
    interval: 1s
    fine:   { resolution: 1s, duration: 5m }
    medium: { resolution: 1m, duration: 1d }
    coarse: { resolution: 1h, duration: 30d }
```

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `dry_run` | bool | `false` | Log each triggered event's description and take no action (no ACLs programmed). |
| `rules_dir` | string | empty | Optional directory of user rule files (`*.yaml`). Files override built-in rules of the same name. |
| `rules_enabled` | list | empty | Rule names to activate. **Required** (non-empty). Names resolve against the embedded predefined rules plus `rules_dir`. |
| `sflow.listen` | string | `0.0.0.0:6343` | UDP listen address for sFlow v5 datagrams. |
| `sample_queue` | int | `65536` | Bounded sample queue (`0` → default). Full queues drop sampled packets instead of growing memory. |
| `event_queue` | int | `1024` | Bounded detector-event queue (`0` → default). |
| `vpp_stats` | block | absent | Present → poll VPP interface counters (enables `vpp.*` metrics). Omitted → no polling, and rules using `vpp.*` are rejected at startup. |
| `vpp_stats.interval` | duration | `1s` | VPP stats polling interval (`0`/omitted → `1s`). |
| `vpp_stats.fine` / `medium` / `coarse` | ring | `1s/5m`, `1m/1d`, `1h/30d` | History rings (same model as a rule's `history`). Each has `resolution` and `duration` (a `0` field uses the default). Windowed `vpp.*` terms aggregate over the coarsest ring that covers their window; a window no ring can cover is rejected at startup. |

### Rule files

Rules live in YAML files, each holding `rules: [ ... ]` with one or more rules. A
curated set is embedded into the binary at build time (the repository `rules/`
directory); operators add or override rules by dropping files into `rules_dir`.
Only the names listed in `rules_enabled` are compiled and run, so a rule needs no
`enabled` flag.

A complete rule with every field written out:

```yaml
rules:
  - name: udp-small-flood
    match:                       # filter: which packets are counted (no field
      family: ipv4               #   contributes to identity by itself).
      proto: udp                 #   proto/ports may be a value or a list.
      src: 0.0.0.0/0             #   src/dst are prefix ranges.
      dst: 0.0.0.0/0
      packet_len: { lt: 100 }    #   filter-only; never enters identity or FlowSpec.
    aggregate:                   # granularity of each descriptor (identity) field.
      proto: exact               #   exact (keep) | all
      src: "/32"                 #   "/N" prefix bits ("/0" = collapse all)
      dst: "/0"
      src_port: all              #   exact | all | "LO-HI" | "N" (bucket step)
      dst_port: all
    history:
      fine:  { resolution: 1s, duration: 10m }
      medium:  { resolution: 1m, duration: 1d }
      coarse: { resolution: 1h, duration: 7d }
      max_instances: 20
    trigger:
      terms:
        short: { metric: pps, window: 10s }
        base:  { metric: pps, window: 10m, offset: 1m }
      expr: "short > 5 * base and short > 100000"
      sustained: 20s
    flowspec:
      action: drop
      ttl: 300s
      refresh: true
      family: "{{family}}"       # every field optional; defaults to descriptor.
      proto: "{{proto}}"
      src_prefix: "{{src}}"
      dst_prefix: "{{dst}}"
      src_port: "{{src_port}}"
      dst_port: "{{dst_port}}"
    description: "udp small-packet flood from {{src}}, pps={{short}}"
```

#### match — what is counted

`match` is a pure filter; it never writes the descriptor. Every field is optional
and an omitted field imposes no constraint. `family` is `ipv4`/`ipv6`; `proto` is
a name/number or a list (`[udp, tcp]`); `src`/`dst` are prefixes (a *range* of
addresses); `src_port`/`dst_port` are a value or list; `packet_len` takes
`lt`/`lte`/`gt`/`gte`. `packet_len` is filter-only — FlowSpec cannot carry it, so
it never enters the identity or the emitted rule.

`tcp_flags` filters on the TCP flags byte: a space/comma list of flag names, each
optionally prefixed with `!` for "must be clear" — e.g. `"syn !ack"` for a SYN
flood. It requires `match.proto: tcp`. It is filter-only for identity, but by
default it is also carried into the emitted FlowSpec, so the drop targets only the
matching flags (e.g. SYN), sparing established connections. Override emission with
`flowspec.tcp_flags` (`all` to emit no flag constraint, or an explicit spec).

#### aggregate — the instance identity

Every matched packet carries concrete values for all fields. Those values form a
comparable *descriptor*; **two packets with the same descriptor are the same
instance**, and `max_instances` therefore counts distinct mitigations (overflow
evicts the lowest-rate instance). `aggregate` sets the granularity of each field;
an omitted field passes through at full granularity. Aggregation depends on the
field's type:

| Field | Type | Forms | Default (pass-through) |
| ----- | ---- | ----- | ---------------------- |
| `family` | categorical | always the concrete family (cannot be aggregated — IPv4 and IPv6 are separate ACLs) | per family |
| `proto` | categorical | `exact` \| `all` | `exact` |
| `src`, `dst` | IP prefix | `"/N"` (binary mask; `/0` collapses all) | `/32` or `/128` |
| `src_port`, `dst_port` | numeric | `exact` \| `all` \| `"LO-HI"` \| `"N"` | `exact` |

For ports: `"22-25"` projects **all** matched packets into the fixed range 22–25
verbatim (no check — use it when `match` already constrained the port and you want
to copy it). `"N"` is a floor bucket of width N: with `"100"`, port 101 maps to
the range **100–199** (buckets are 0–99, 100–199, …; the inclusive top is N−1, not
N). `all` collapses every port to the wildcard 0–65535.

Ports only exist for TCP/UDP. A packet with no ports (ICMP, etc.) — or any packet
when `aggregate.proto` is `all` — is treated as "ports not applicable": the port
fields become wildcard, so they neither split the identity nor appear in the
emitted rule. So you don't need to set ports to `all` on an ICMP rule; just omit
them. The only compile-time restriction is that a non-wildcard port aggregate
cannot be combined with `aggregate.proto: all` (a FlowSpec port range needs a
concrete protocol).

#### history — the per-instance rings

Each instance keeps up to three fixed-capacity ring buffers. `fine` is required
(second-level triggers); `medium` and `coarse` are optional coarser rollups for
longer context. Each ring is `{ resolution, duration }` and `duration` must be a multiple
of `resolution` (slot count = duration ÷ resolution). Memory is bounded by
`max_instances` × the ring sizes, so pick resolutions that cover your longest
trigger window without over-allocating. Example: `fine {1s, 10m}` = 600 slots,
`medium {1m, 1d}` = 1440 slots, `coarse {1h, 7d}` = 168 slots.

#### trigger — when to emit

`terms` are named windowed aggregates; `expr` is a free-form boolean expression
over them; `sustained` debounces. A term has:

- `metric`: one of
  - `pps` (default) / `bps` — sampled flow rate from this rule's history rings.
  - A VPP stats metric (read from the stats poller, see below). A rule using any
    of them requires a `vpp_stats:` block under the detector — otherwise the agent
    **refuses to start** rather than let the term silently read 0. `window` is
    optional: omit it to read the latest poll (instant); set it to aggregate over
    the `vpp_stats` rings (with `offset` and `agg: avg|max`, default `avg` — `sum`
    is rejected for these rate metrics).

  VPP stats metrics come in two scopes:
  - `vpp.packet_iface.<field>` — the interface the instance's packets entered on
    (its last-seen ingress interface).
  - `vpp.total.<field>` — the sum across all VPP interfaces.

  `<field>` is one of:

  | field | meaning |
  | --- | --- |
  | `rx_pps` / `tx_pps` | packets/s received / transmitted on the interface |
  | `rx_bps` / `tx_bps` | bits/s received / transmitted on the interface |
  | `sw_drop_pps` | packets/s dropped by VPP's forwarding graph (`/if/drops`) — **includes this agent's own ACL deny** |
  | `hw_drop_pps` | packets/s dropped by the NIC RX ring overflow (`/if/rx-miss`) — the hardware "can't keep up" signal |

  So e.g. `vpp.total.rx_bps` is the box-wide inbound bit rate, and
  `vpp.packet_iface.hw_drop_pps` is NIC-level loss on the attacked interface.
  There is **no** `drop_bps`: VPP's drop counters are packets-only.
- `window`: the span aggregated (required for `pps`/`bps`; optional for `vpp.*`, where omitting it reads the latest poll).
- `offset` (optional): how far back the window *ends* — `{window: 10m, offset: 1m}`
  covers `[now−11m, now−1m]`. Use it to build a baseline that excludes the recent
  spike.
- `agg` (optional): `avg` (default; rate over the window), `max` (peak single-slot
  rate), or `sum` (total count).

`expr` supports arithmetic (`+ - * /`), comparison (`> >= < <= == !=`) and boolean
(`and or not`) over the term values, e.g. `short > 5 * base and short > 100000`.
It is compiled once at load (via `expr-lang/expr`) and evaluated on a periodic
tick over the bounded instance set — **not per packet** — so windowed comparisons
cost the same at any traffic rate. Each term reads from the coarsest history ring
whose resolution divides both `window` and `offset`, so long-window terms stay
cheap; `window` and `offset` must be multiples of some ring resolution that covers
them. `sustained` requires `expr` to hold continuously for that duration before an
event fires (a zero/absent `sustained` fires on the first true tick).

> Always pair a relative comparison with an absolute floor. If the baseline term is
> zero (e.g. a brand-new source), `short > 5 * base` reduces to `short > 0` and a
> ratio alone would fire on any traffic; the `and short > 100000` clause is the
> guard.

#### flowspec — what is emitted

`action` (`drop`), `ttl` and the TTL `refresh` flag are emission metadata. Each
match field — `family`, `proto`, `src_prefix`, `dst_prefix`, `src_port`,
`dst_port` — is optional and **defaults to the descriptor value**. Override a
field by writing a template (`"{{src}}"`, or a literal), or write `all`/`any` to
widen it to a wildcard. A field whose descriptor value is a wildcard (e.g. an
aggregate of `/0` or `all`) emits no constraint. Because identity is the
descriptor (not the emitted rule), the FlowSpec may legitimately be wider than the
identity — e.g. detect a host scanning port 22 but block all of its traffic by
aggregating `proto`/ports to `all`.

Template variables are the descriptor fields `{{family}}`, `{{proto}}`, `{{src}}`,
`{{dst}}`, `{{src_port}}`, `{{dst_port}}`; `description` may additionally use
`{{ingress_if}}` and the trigger term names (e.g. `{{short}}`). An unknown
variable is rejected at load time.

---

## log

```yaml
log:
  level: info
  format: text
```

| Field    | Type   | Default | Description |
| -------- | ------ | ------- | ----------- |
| `level`  | string | `info`  | `debug` / `info` / `warn` / `error`. `debug` logs per-rule apply/dedup detail. |
| `format` | string | `text`  | `text` or `json`. Prefer `json` for container/collector setups. |

Logs are written to **stderr**. Ignored rules are logged at `warn` level with
`reason`, `detail`, `family`, `peer` and `original_flowspec` fields for triage.
