# Configuration reference

> 🌐 **English** · [中文](../zh/configuration.md)

The agent is started with a single YAML config file, default path
`/etc/flowspec-vpp-agent/config.yaml` (override with `--config` / `-c`). In the compose
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

**Coexistence with manual ACLs.** The agent does not clobber an interface's ACL
list. On attach it preserves any pre-existing (manually-configured) ACLs and
appends its own pair **last** within the managed direction. VPP matches a list in
order, first match wins, so a manual `permit`/`deny` keeps precedence over ours —
the agent's Managed ACLs act as the final policy. (Each Managed ACL ends in a
`permit-any`, which is why ours must come last: placed earlier it would shadow any
manual ACL behind it.) Only ACLs carrying the agent's own tag are touched; on a
clean exit they are removed from those interfaces and the rest of the list is left
intact.

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
  builtin_rules: true        # auto-enable all embedded built-ins (default)
  rules_enabled: []          # extra rules (e.g. from rules_dir) merged on top
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
| `builtin_rules` | bool | `true` | Auto-enable every embedded built-in rule. The effective set is the built-ins (when enabled) merged with `rules_enabled`. |
| `rules_enabled` | list | empty | Extra rule names to activate, merged with the built-ins — this is how you enable a `rules_dir` rule. With `builtin_rules: false` it instead selects a subset of built-ins. Names resolve against the built-ins plus `rules_dir`. With `builtin_rules: false` and an empty list, the config is rejected (nothing to run). |
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
By default (`builtin_rules: true`) every built-in is active; `rules_enabled` merges
in additional rules by name (e.g. ones from `rules_dir`). Set `builtin_rules: false`
to instead run only the subset named in `rules_enabled`. A rule needs no `enabled`
flag of its own.

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

`icmp_type` / `icmp_code` filter on the ICMP/ICMPv6 type and code (0–255, a value
or list). They only ever match `icmp`/`icmpv6` packets — a rule that sets either
never matches non-ICMP traffic. Use them to scope a rule to specific types (e.g.
count only echo-request floods).

#### aggregate — the instance identity

Every matched packet carries concrete values for all fields. Those values form a
comparable *descriptor*; **two packets with the same descriptor are the same
instance**, and `max_instances` therefore counts distinct mitigations (overflow
keeps the heaviest by the admission sketch — see history below). `aggregate` sets
the granularity of each field; an omitted field passes through at full
granularity. Aggregation depends on the field's type:

| Field | Type | Forms | Default (pass-through) |
| ----- | ---- | ----- | ---------------------- |
| `family` | categorical | always the concrete family (cannot be aggregated — IPv4 and IPv6 are separate ACLs) | per family |
| `proto` | categorical | `exact` \| `all` | `exact` |
| `src`, `dst` | IP prefix | `"/N"` (binary mask; `/0` collapses all) | `/32` or `/128` |
| `src_port`, `dst_port` | numeric | `exact` \| `all` \| `"LO-HI"` \| `"N"` | `exact` |
| `icmp_type`, `icmp_code` | numeric (ICMP) | `exact` \| `all` | `exact` |

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

`icmp_type`/`icmp_code` are the ICMP equivalent, applicable only to `icmp`/`icmpv6`
packets (wildcard for everything else). They default to `exact`, so each type/code
is its own instance **and is emitted into the drop** — meaning a flood of one
ICMPv6 type (e.g. echo-request, 128) is dropped without blocking Neighbor Discovery
(NS/NA/RS/RA, types 133–137), which would otherwise break IPv6 connectivity. Set
`icmp_type: all` / `icmp_code: all` to wildcard a field (drop all ICMP to the
victim). The built-in `icmp-flood-*` rules use `icmp_type: exact, icmp_code: all`.

#### history — the per-instance rings

Each instance keeps up to three fixed-capacity ring buffers. `fine` is required
(second-level triggers); `medium` and `coarse` are optional coarser rollups for
longer context. Each ring is `{ resolution, duration }` and `duration` must be a multiple
of `resolution` (slot count = duration ÷ resolution). Memory is bounded by
`max_instances` × the ring sizes, so pick resolutions that cover your longest
trigger window without over-allocating. Example: `fine {1s, 10m}` = 600 slots,
`medium {1m, 1d}` = 1440 slots, `coarse {1h, 7d}` = 168 slots.

##### How the `max_instances` slots are filled (admission)

`max_instances` bounds how many targets get full ring sets — but **every** matched
target is observed cheaply by a per-rule [HeavyKeeper](https://www.usenix.org/conference/atc18/presentation/gong)
sketch (a few KB, fixed memory) that estimates each target's recent weighted
volume. The full-instance pool holds the **heaviest** targets by that estimate:

- A new target is admitted immediately while the pool has room.
- When the pool is full, a newcomer is admitted only if its sketch estimate
  exceeds the weakest current instance's — then that instance is evicted. Because
  the sketch has watched both over recent traffic, this is an *accumulated*
  comparison, so a genuinely heavier new attack always displaces a lighter one
  and never starves (older builds compared a single sample and could freeze the
  table once full).
- The sketch ages on every tick, so a target that goes quiet fades and frees its
  standing; a pulsing target that keeps bursting does not.

**`rank` (rule field).** By default the sketch weights each target by packet rate
over a ~30 s half-life. Set `rank: <term-name>` to rank by a trigger term's metric
and window instead: a `bps` term ranks by **bytes** (so a reflection rule keeps
its highest-*bps* victims, not highest-pps), and the sketch's decay half-life
becomes that term's window, so the rank estimate is smoothed over the same span
the term spans (not raw per-second pps). The named term must be a `pps`/`bps` term
(a `vpp.*` term is interface-level and cannot rank). The built-in reflection rules
use `rank: rate`.

The `/status` endpoint reports each instance's current sketch estimate as
`score` (packets/s, or bytes/s under a bps `rank`). Raising `max_instances` widens
the pool; the cost is `max_instances` × ring memory plus a small fixed sketch
(sized from `max_instances`).

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
`dst_port`, `icmp_type`, `icmp_code` — is optional and **defaults to the descriptor
value**. Override a field by writing a template (`"{{src}}"`, or a literal), or
write `all`/`any` to widen it to a wildcard. A field whose descriptor value is a
wildcard (e.g. an aggregate of `/0` or `all`) emits no constraint. Because identity
is the descriptor (not the emitted rule), the FlowSpec may legitimately be wider
than the identity — e.g. detect a host scanning port 22 but block all of its
traffic by aggregating `proto`/ports to `all`.

Template variables are the descriptor fields `{{family}}`, `{{proto}}`, `{{src}}`,
`{{dst}}`, `{{src_port}}`, `{{dst_port}}`, `{{icmp_type}}`, `{{icmp_code}}`;
`description` may additionally use `{{ingress_if}}` and the trigger term names
(e.g. `{{short}}`). An unknown variable is rejected at load time.

---

## persist

```yaml
persist: /etc/flowspec-vpp-agent/persist.dump
```

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `persist` | string | `<config dir>/persist.dump` | **Top-level** path of the state dump (detector rule history + VPP stats rings), written on shutdown and reloaded on startup so detection resumes from recent history after a quick restart. When omitted it defaults to `persist.dump` next to the config file; set an explicit path to relocate it. Only used when the detector runs. |

On reload, history is restored **only** into entries that still match. An entry is skipped when:

- the rule was **removed** or **renamed** (no current rule has that name), or
- the rule's **definition changed** — the entire rule config (match, aggregate, history sizing **including `max_instances`**, trigger, flowspec, rank, description) is hashed into a fingerprint, and a changed fingerprint reloads nothing for that rule, or
- a VPP-stats interface's **ring shape changed** (resolution/duration).

This is intentional: history written under a different definition could mean something else, so a changed rule starts fresh. The admission sketch is never persisted (it rebuilds within a half-life).

---

## log

Logging fans out to one or more **sinks**, each filtered independently by **level**
and **scope**. Omitting the whole `log` block keeps the default: stderr at `info`,
all scopes, text format.

```yaml
log:
  stderr:                       # default sink, always active (omit => info/all/text)
    level: info
    scope: all
    format: text
  telegram:                     # optional; present => enabled
    bot_token: "123456:ABC-DEF"
    chat_id: "-1001234567890"
    level: info
    scope: [detector, acl]      # only detector events + ACL changes
    format: text
```

### Scopes

Every log record carries one **scope** (the subsystem that emitted it). A sink's
`scope` selects which it receives: `all`, `none` (disable the sink), a single
scope, or a list.

| Scope | Covers |
| --- | --- |
| `core` | startup/shutdown, config, HTTP endpoint, state load/save |
| `bgp` | BGP speaker and per-peer sessions |
| `acl` | FlowSpec rule **apply / update / withdraw** (the desired ACL set changing) |
| `vpp` | VPP connect/reconnect, ACL attach/cleanup, low-level replace |
| `detector` | detector events (announce/expire), sFlow, VPP-stats polling, leases |

So `scope: [detector, acl]` delivers detector events and FlowSpec rule changes
**without** VPP connect/attach chatter — handy for an alerting sink.

### stderr

| Field | Type | Default | Description |
| -------- | ------ | ------- | ----------- |
| `level` | string | `info` | `debug` / `info` / `warn` / `error`. `debug` adds per-rule dedup detail. |
| `scope` | scope | `all` | `all` / `none` / a scope / a list. |
| `format` | string | `text` | `text` or `json`. Prefer `json` for container/collector setups. |

### telegram

Present ⇒ enabled. Records are formatted (text/json), **batched**, and delivered to
a chat via the Telegram Bot API. The sink is fully asynchronous: it never blocks
logging, and if its bounded queue overflows it drops lines (reporting
`[N log lines dropped]` on the next message) rather than stalling the agent.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `bot_token` | string | — | **Required.** BotFather token. |
| `chat_id` | string | — | **Required.** Target chat/channel id. |
| `level` | string | `info` | As stderr. |
| `scope` | scope | `all` | As stderr. |
| `format` | string | `text` | As stderr. |

> **Security:** `bot_token` is a credential and Telegram is an external service —
> messages (including any data in log fields) leave the box and may be retained by
> Telegram. Keep the token out of shared/committed configs and scope the sink to
> what you actually need to see remotely.

Logs are written to **stderr** by default. Ignored rules are logged at `warn` with
`reason`, `detail`, `family`, `peer` and `original_flowspec` fields for triage.

> The CLI overrides the config path: `--config` / `-c`.

