# 配置文件详解

> 🌐 [English](../en/configuration.md) · **中文**

agent 通过一个 YAML 配置文件启动，默认路径为
`/etc/flowspec-vpp-agent/config.yaml`（可用 `-config` 覆盖）。compose 部署时把宿主机的
`./config` 目录只读挂载到 `/etc/flowspec-vpp-agent`，agent 读取其中的 `config.yaml`。

下面按段落逐项说明。完整示例见
[../../deploy/config.example.yaml](../../deploy/config.example.yaml)。

> 所有字段都有默认值，缺省即采用默认。配置在启动时会做校验，非法值会让进程以非零码退出并打印原因。

---

## vpp

VPP 连接相关。

```yaml
vpp:
  socket: /run/vpp/api.sock
  stats_socket: /run/vpp/stats.sock
```

| 字段           | 类型   | 默认值                  | 说明 |
| -------------- | ------ | ----------------------- | ---- |
| `socket`       | string | `/run/vpp/api.sock`     | VPP **binary API** unix socket 路径。agent 通过它下发 `acl_add_replace`、枚举接口、挂载 ACL。**必填**（不能为空）。 |
| `stats_socket` | string | `/run/vpp/stats.sock`   | VPP stats socket 路径。**第一版保留字段，暂未使用**；写上不影响运行，便于后续接入计数器。 |

> 容器里访问 socket：`/run/vpp` 通常 root（或 vpp 组）持有，compose 用 `user: "0:0"` 最省事；socket 未就绪或 VPP 重启时 agent 会退避重连，不会启动即崩。

---

## bgp

内嵌 GoBGP speaker。每个 peer 即一个 FlowSpec 会话。

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

| 字段        | 类型   | 默认值            | 说明 |
| ----------- | ------ | ----------------- | ---- |
| `listen`    | string | `0.0.0.0:10179`   | BGP 监听 `host:port`。**默认 10179 而非 179**，避开宿主机上常驻的原生 BGP 守护程序。必须是合法 `host:port`，端口 1–65535。 |
| `router_id` | string | 空                | BGP Router ID，点分四段（IPv4 形式）。留空则由 GoBGP 自行决定；建议显式配置。填写时必须是合法 IP 地址。 |
| `asn`       | uint32 | `0`               | 本地 AS 号。 |
| `peers`     | list   | 空                | FlowSpec 会话列表，见下。可配置多个，规则会按引用计数合并进同一组 Managed ACL。 |

### bgp.peers[]

| 字段       | 类型   | 默认值 | 说明 |
| ---------- | ------ | ------ | ---- |
| `address`  | string | —      | 邻居 IP 地址。**必填且必须合法**。 |
| `peer_asn` | uint32 | —      | 邻居 AS 号。**必填且不能为 0**。 |
| `port`     | uint16 | `0`    | 邻居 TCP 传输端口；`0` 表示用默认。FlowSpec 采集器（如 FastNetMon）通常主动连入，一般无需设置。 |
| `passive`  | bool   | `false`| 被动模式（只监听、不主动发起）。FlowSpec 采集场景常设为 `true`。 |

每个会话在协商时同时启用 IPv4 与 IPv6 FlowSpec 地址族。

---

## interfaces

Managed ACL 挂到哪些接口、什么方向（本地策略，FlowSpec 报文不携带接口信息）。

```yaml
interfaces:
  mode: all
  direction: ingress
  # list:
  #   - GigabitEthernet0/0/0
```

| 字段        | 类型   | 默认值     | 说明 |
| ----------- | ------ | ---------- | ---- |
| `mode`      | string | `all`      | `all` = 全部数据面接口（自动排除 `local0` 一类）；`list` = 仅 `list` 中列出的接口。其他值非法。 |
| `list`      | list   | 空         | 当 `mode: list` 时**必填且非空**，元素为 VPP 接口名（如 `GigabitEthernet0/0/0`）。`mode: all` 时忽略。 |
| `direction` | string | `ingress`  | ACL 应用方向，`ingress` 或 `egress`。串接（bump-in-the-wire）部署下默认 `ingress` 即覆盖全部入向流量。 |

---

## metrics

Prometheus 指标与健康检查的 HTTP 端点。

```yaml
metrics:
  listen: ""
```

| 字段     | 类型   | 默认值 | 说明 |
| -------- | ------ | ------ | ---- |
| `listen` | string | 空字符串 | 空值表示不启动 HTTP 监听。设置为合法 `host:port`（如 `127.0.0.1:9469` 或 `0.0.0.0:9469`）后才暴露 `/metrics` 和 `/healthz`；`healthcheck` 子命令会请求本机该端口的 `/healthz`。 |

暴露的指标：

- `flowspec_rules_ignored_total{reason,family,peer}` —— 被忽略（无法等价转换）的规则数。`reason` 至少区分 `unsupported_component` / `unsupported_expression` / `unsupported_action` / `unmappable_prefix`。**建议对该指标的增长率配置告警**：一条被静默丢弃的规则意味着一次未被缓解的攻击。
- `flowspec_rules_applied_total{family,peer}` —— 成功下发的规则数。
- `flowspec_acl_entries{family}` —— 当前每个 Managed ACL 的 entry 数量（gauge）。

---

## log

```yaml
log:
  level: info
  format: text
```

| 字段     | 类型   | 默认值  | 说明 |
| -------- | ------ | ------- | ---- |
| `level`  | string | `info`  | `debug` / `info` / `warn` / `error`。`debug` 会打印每条规则的下发/去重细节。 |
| `format` | string | `text`  | `text` 或 `json`。容器/采集场景建议 `json`。 |

日志写到 **stderr（标准错误）**。被忽略的规则会在 `warn` 级别记录，包含 `reason`、`detail`、`family`、`peer`、`original_flowspec` 等字段，便于排查。
