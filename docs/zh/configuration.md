# 配置文件详解

> 🌐 [English](../en/configuration.md) · **中文**

agent 通过一个 YAML 配置文件启动，默认路径为
`/etc/flowspec-vpp-agent/config.yaml`（可用 `-config` 覆盖）。compose 部署时把宿主机的
`./config` 目录只读挂载到 `/etc/flowspec-vpp-agent`，agent 读取其中的 `config.yaml`。

下面按段落逐项说明。完整示例见
[../../deploy/config.example.yaml](../../deploy/config.example.yaml)。

> 标明默认值的字段可省略；必填字段会在下文明确标出。配置在启动时会做校验，非法值会让进程以非零码退出并打印原因。

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
| `stats_socket` | string | `/run/vpp/stats.sock`   | VPP stats socket 路径。启用 `local_detector.vpp_stats` 时用于读取接口计数器。 |

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
| `router_id` | string | —                 | BGP Router ID，点分四段（IPv4 形式）。**必填**；GoBGP 会拒绝空 Router ID。 |
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

## local_detector

可选的本机 sFlow/VPP-stats 检测器。它监听 sFlow v5 UDP 数据包，维护固定容量规则状态，
把命中的事件转换成 synthetic FlowSpec 规则走同一条 manager/VPP ACL 路径，并负责 TTL
刷新与到期撤销。

```yaml
local_detector:
  enabled: true
  rules_dir: /etc/flowspec-vpp-agent/rules
  rules_enabled:
    - udp-small-flood
    - ssh-scan-ipv4
    - ssh-scan-ipv6
  sflow:
    listen: "0.0.0.0:6343"
  sample_queue: 65536
  event_queue: 1024
  vpp_stats:
    enabled: true
    interval: 1s
```

| 字段 | 类型 | 默认值 | 说明 |
| ---- | ---- | ------ | ---- |
| `enabled` | bool | `false` | 是否启用本机检测器。 |
| `dry_run` | bool | `false` | 仅记录触发事件的 description，不下发任何 ACL。 |
| `rules_dir` | string | 空 | 可选的用户规则目录（`*.yaml`）。同名文件覆盖内置规则。 |
| `rules_enabled` | list | 空 | 要启用的规则名列表。启用检测器时必填；名字在内置预定义规则与 `rules_dir` 中解析。 |
| `sflow.listen` | string | `0.0.0.0:6343` | sFlow v5 UDP 监听地址。 |
| `sample_queue` | int | `65536` | 有界 sample 队列；处理不过来时丢采样，不增长内存。 |
| `event_queue` | int | `1024` | 有界事件队列。 |
| `vpp_stats.enabled` | bool | `true` | 是否轮询 VPP 接口计数器并写入固定 ring。 |
| `vpp_stats.interval` | duration | `1s` | VPP stats 轮询周期。 |

### 规则文件

规则放在 YAML 文件里，每个文件含 `rules: [ ... ]`（一个或多个规则）。一套精选规则在
编译时内嵌进二进制（仓库的 `rules/` 目录）；运维可在 `rules_dir` 放文件来新增或覆盖。
只有 `rules_enabled` 列出的名字会被编译运行，因此规则本身不需要 `enabled` 字段。

把每个字段都写全的完整规则：

```yaml
rules:
  - name: udp-small-flood
    match:                       # 过滤：哪些包被统计（任何字段本身都不构成身份）。
      family: ipv4               #   proto/端口可为单值或列表。
      proto: udp
      src: 0.0.0.0/0             #   src/dst 是前缀范围。
      dst: 0.0.0.0/0
      packet_len: { lt: 100 }    #   仅过滤；永不进入身份或 FlowSpec。
    aggregate:                   # 每个描述符（身份）字段的granularity。
      proto: exact               #   exact（保留）| all
      src: "/32"                 #   "/N" 前缀位（"/0" = 全部聚合）
      dst: "/0"
      src_port: all              #   exact | all | "LO-HI" | "N"（分桶步长）
      dst_port: all
    history:
      fine:  { resolution: 1s, duration: 10m }
      medium:  { resolution: 1m, duration: 1d }
      coarse: { resolution: 1h, duration: 7d }
      max_instances: 200
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
      family: "{{family}}"       # 每个字段均可选，默认取描述符值。
      proto: "{{proto}}"
      src_prefix: "{{src}}"
      dst_prefix: "{{dst}}"
      src_port: "{{src_port}}"
      dst_port: "{{dst_port}}"
    description: "udp small-packet flood from {{src}}, pps={{short}}"
```

#### match —— 统计哪些包

`match` 是纯过滤层，不写描述符。每个字段可选,省略即不约束。`family` 为 `ipv4`/`ipv6`；
`proto` 为名字/编号或列表（`[udp, tcp]`）；`src`/`dst` 为前缀（一个地址*范围*）；
`src_port`/`dst_port` 为单值或列表；`packet_len` 支持 `lt`/`lte`/`gt`/`gte`。`packet_len`
仅用于过滤——FlowSpec 无法承载，因此它绝不进入身份或下发规则。

#### aggregate —— 实例身份

每个命中包都带着所有字段的具体值。这些值组成一个可比较的*描述符*；**描述符相同即同一实例**，
因此 `max_instances` 计的是不同的缓解动作（溢出时淘汰速率最低的实例）。`aggregate` 设定每个
字段的granularity；省略的字段按完整granularity透传。聚合方式按字段类型不同：

| 字段 | 类型 | 形式 | 默认（透传） |
| ---- | ---- | ---- | ------------ |
| `family` | 分类 | 始终是具体 family（不可聚合——IPv4/IPv6 是两套独立 ACL） | 按 family |
| `proto` | 分类 | `exact` \| `all` | `exact` |
| `src`、`dst` | IP 前缀 | `"/N"`（二进制掩码；`/0` 全聚合） | `/32` 或 `/128` |
| `src_port`、`dst_port` | 数字 | `exact` \| `all` \| `"LO-HI"` \| `"N"` | `exact` |

端口的几种形式：`"22-25"` 把**所有**命中包照抄投影到固定范围 22–25（不校验——适用于 `match`
已限定端口、这里照抄的场景）；`"N"` 是宽度 N 的向下取整分桶,如 `"100"` 时端口 101 落到
**100–199**（分桶为 0–99、100–199……，上界是 N−1 而非 N）；`all` 把所有端口聚合为通配
0–65535。

由于 FlowSpec 端口范围需要具体的 tcp/udp 协议,非通配端口要求 `match.proto` 为 tcp 和/或 udp
且 `aggregate.proto` 不为 `all`,否则编译失败（非 TCP/UDP 规则请把端口聚合为 `all`）。

#### history —— 每实例的环形缓冲

每个实例最多维护三个固定容量环。`fine` 必填（秒级触发）；`medium`/`coarse` 是可选的更粗 rollup,
用于更长周期上下文。每个环为 `{ resolution, duration }`,且 `duration` 必须是 `resolution`
的整数倍（槽数 = duration ÷ resolution）。内存上界 = `max_instances` × 各环大小,因此分辨率
要能覆盖最长的触发窗口又不过度分配。例如 `fine {1s, 10m}` = 600 槽,`medium {1m, 1d}` = 1440 槽,
`coarse {1h, 7d}` = 168 槽。

#### trigger —— 何时下发

`terms` 是命名窗口聚合；`expr` 是其上的自由布尔表达式；`sustained` 去抖。term 含：

- `metric`：`pps`、`bps`,或 VPP 接口计数器 `vpp.ingress.rx_pps`、`vpp.ingress.tx_pps`、
  `vpp.ingress.drop_pps`（按实例最近的 `ingress_if` 查找）。
- `window`：聚合的时间跨度。
- `offset`（可选）：窗口*结束点*往回退多远——`{window: 10m, offset: 1m}` 覆盖 `[now−11m, now−1m]`,
  用于构造排除近期突增的基线。
- `agg`（可选）：`avg`（默认,窗口速率）、`max`（单槽峰值速率）、`sum`（总量）。

`expr` 支持算术（`+ - * /`）、比较（`> >= < <= == !=`）和布尔（`and or not`）运算,如
`short > 5 * base and short > 100000`。它在加载时编译一次（用 `expr-lang/expr`）,按周期 tick
遍历有界实例集求值——**不在每个包上跑**——因此窗口比较在任何流量速率下成本相同。每个 term 从
“能整除其 `window` 与 `offset` 的最粗历史环”读取,长窗口因此很廉价；`window` 与 `offset` 必须
是某个能覆盖它们的环分辨率的整数倍。`sustained` 要求 `expr` 持续成立该时长才发事件（为 0 或省略
则首次为真即发）。

> 相对比较务必搭配绝对地板项。若基线 term 为 0（如全新的源）,`short > 5 * base` 退化为
> `short > 0`,只有比值会对任何流量触发；`and short > 100000` 这一项才是兜底。

#### flowspec —— 下发什么

`action`（`drop`）、`ttl` 与 TTL 的 `refresh` 标志是下发元数据。每个 match 字段——`family`、
`proto`、`src_prefix`、`dst_prefix`、`src_port`、`dst_port`——均可选,且**默认取描述符的值**。
写模板（`"{{src}}"` 或字面量）可覆盖,写 `all`/`any` 可放宽为通配。描述符值本身为通配的字段
（如聚合为 `/0` 或 `all`）不下发该约束。由于身份是描述符（而非下发规则）,FlowSpec 可以合法地
比身份更宽——例如检测某主机扫 22 端口,但通过把 `proto`/端口聚合为 `all` 来封禁它的全部流量。

模板变量为描述符字段 `{{family}}`、`{{proto}}`、`{{src}}`、`{{dst}}`、`{{src_port}}`、
`{{dst_port}}`；`description` 还可用 `{{ingress_if}}` 与触发 term 名（如 `{{short}}`）。未知
变量在加载时报错。

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
