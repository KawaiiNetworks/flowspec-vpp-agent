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
| `stats_socket` | string | `/run/vpp/stats.sock`   | VPP stats socket path. **Reserved in the first version, currently unused**; setting it is harmless and eases future stats integration. |

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

Each session negotiates both IPv4 and IPv6 FlowSpec address families.

---

## interfaces

Where the Managed ACLs are applied, and in which direction (local policy —
FlowSpec carries no interface information).

```yaml
interfaces:
  mode: all
  direction: ingress
  # list:
  #   - GigabitEthernet0/0/0
```

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
| `listen` | string | empty string | Empty disables the HTTP listener. Set a valid `host:port` such as `127.0.0.1:9469` or `0.0.0.0:9469` to expose `/metrics` and `/healthz`; the `healthcheck` subcommand requests `/healthz` on that port locally. |

Exposed metrics:

- `flowspec_rules_ignored_total{reason,family,peer}` — rules ignored because they
  cannot be equivalently mapped. `reason` distinguishes at least
  `unsupported_component` / `unsupported_expression` / `unsupported_action` /
  `unmappable_prefix`. **Alert on the rate of this metric**: a silently dropped
  rule means an unmitigated attack.
- `flowspec_rules_applied_total{family,peer}` — rules accepted and applied.
- `flowspec_acl_entries{family}` — current entry count of each Managed ACL (gauge).

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
