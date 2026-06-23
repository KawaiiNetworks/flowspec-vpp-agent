# 配置文件详解

> 🌐 [English](../en/configuration.md) · **中文**

agent 通过一个 YAML 配置文件启动，默认路径为
`/etc/flowspec-vpp-agent/config.yaml`（可用 `--config` / `-c` 覆盖）。compose 部署时把宿主机的
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
| `stats_socket` | string | `/run/vpp/stats.sock`   | VPP stats socket 路径。配置了 `detector.vpp_stats` 块时用于读取接口计数器。 |

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
| `receive`  | bool   | `true` | 接收该 peer 的 FlowSpec：应用到 VPP，并转发给 `send` peer。对只向其发布的上游可设为 `false`。 |
| `send`     | bool   | `false`| 向该 peer 发布我们的整张 FlowSpec 表（包括从 `receive` peer 收到的规则和检测器产生的 drop）。 |

每个 peer 必须至少有 `receive` 或 `send`；`receive: false` 且 `send: false` 会被拒绝。
每个会话在协商时同时启用 IPv4 与 IPv6 FlowSpec 地址族。

**方向由 GoBGP 策略强制实施。** 导出策略（默认 reject）只允许把我们产生/转发的
FlowSpec 发给 `send` peer——因此非 send peer 即使协商了该地址族也收不到我们的路由；
导入策略（默认 reject）使非 `receive` peer 的路由不进入本地 RIB，从而不会被转发；
入向是否应用到 VPP 则按 peer 单独控制。

本 agent 只会**originate** 纯 drop（`traffic-rate 0`）；转发的路由按收到的原样发出。

---

## acl

Managed ACL 如何应用到数据面（本地策略，FlowSpec 报文不携带接口信息）。

```yaml
acl:
  interfaces:
    mode: all
    direction: ingress
    # list:
    #   - GigabitEthernet0/0/0
```

### acl.interfaces

Managed ACL 挂到哪些接口、什么方向。

| 字段        | 类型   | 默认值     | 说明 |
| ----------- | ------ | ---------- | ---- |
| `mode`      | string | `all`      | `all` = 全部数据面接口（自动排除 `local0` 一类）；`list` = 仅 `list` 中列出的接口。其他值非法。 |
| `list`      | list   | 空         | 当 `mode: list` 时**必填且非空**，元素为 VPP 接口名（如 `GigabitEthernet0/0/0`）。`mode: all` 时忽略。 |
| `direction` | string | `ingress`  | ACL 应用方向，`ingress` 或 `egress`。串接（bump-in-the-wire）部署下默认 `ingress` 即覆盖全部入向流量。 |

**与手动 ACL 共存。** agent 不会清空接口的 ACL 列表。挂载时它保留接口上已有的（手动配置的）
ACL，把自己那对 Managed ACL 追加到所管理方向的**最后**。VPP 按列表顺序匹配、首条命中即停，
因此手动的 `permit`/`deny` 优先级高于我们的——我们的 Managed ACL 充当兜底策略。（每个 Managed
ACL 以 `permit-any` 结尾，这正是我们必须放最后的原因：若放在前面，会把它后面的手动 ACL 全部
遮蔽。）只有携带 agent 自身标记的 ACL 会被改动；干净退出时把它们从这些接口上摘掉，列表其余部分
原样保留。

---

## metrics

Prometheus 指标与健康检查的 HTTP 端点。

```yaml
metrics:
  listen: ""
```

| 字段     | 类型   | 默认值 | 说明 |
| -------- | ------ | ------ | ---- |
| `listen` | string | 空字符串 | 空值表示不启动 HTTP 监听。设置为合法 `host:port`（如 `127.0.0.1:9469` 或 `0.0.0.0:9469`）后才暴露 `/metrics`、`/healthz` 和 `/status`；`healthcheck` 子命令会请求本机该端口的 `/healthz`。 |

暴露的指标：

- `flowspec_rules_ignored_total{reason,family,peer}` —— 被忽略（无法等价转换）的规则数。`reason` 至少区分 `unsupported_component` / `unsupported_expression` / `unsupported_action` / `unmappable_prefix`。**建议对该指标的增长率配置告警**：一条被静默丢弃的规则意味着一次未被缓解的攻击。
- `flowspec_rules_applied_total{family,peer}` —— 成功下发的规则数。
- `flowspec_acl_entries{family}` —— 当前每个 Managed ACL 的 entry 数量（gauge）。

### `/status`（JSON）

同一监听端口上的 `GET /status` 返回检测器实时状态的 JSON 快照（检测器未启用时各段为空）：

- `traffic` —— VPP stats 轮询得到的每接口最新速率（`rx_pps` / `tx_pps` / `rx_bps` / `tx_bps` / `sw_drop_pps` / `hw_drop_pps`）。
- `rules` —— 每条检测规则及其占用（`instance_count` / `max_instances`）与当前实例。每个实例携带其描述符（family、proto、src/dst、端口）、来自 fine ring 的当前 `pps` / `bps`、求值后的触发项 `terms`，以及 `firing`（触发表达式当前是否成立）。
- `active` —— 当前通过 manager 下发的 synthetic FlowSpec 租约，含 `flowspec` 标识、`family` 与 `expires_at`。

`rules` 与 `active` 每个检测 tick 刷新一次，`traffic` 为最近一次轮询。该端点只读且无鉴权 —— 请将 `listen` 绑定到可信地址。

---

## detector

可选的 sFlow/VPP-stats 检测器。它监听 sFlow v5 UDP 数据包，维护固定容量规则状态，
把命中的事件转换成 synthetic FlowSpec 规则走同一条 manager/VPP ACL 路径，并负责 TTL
刷新与到期撤销。

**检测器由 `detector:` 段的存在来启用** —— 没有 `enabled` 开关。同理，`vpp_stats`
由 `vpp_stats:` 块的存在来启用；省略对应段即关闭。

```yaml
detector:
  rules_dir: /etc/flowspec-vpp-agent/rules
  builtin_rules: true        # 自动启用全部内置规则（默认）
  rules_enabled: []          # 额外合并的规则名（例如 rules_dir 里的）
  sflow:
    listen: "0.0.0.0:6343"
  sample_queue: 65536
  event_queue: 1024
  vpp_stats:       # 写了这个块即开启计数器轮询；省略则关闭
    interval: 1s
    fine:   { resolution: 1s, duration: 5m }
    medium: { resolution: 1m, duration: 1d }
    coarse: { resolution: 1h, duration: 30d }
```

| 字段 | 类型 | 默认值 | 说明 |
| ---- | ---- | ------ | ---- |
| `dry_run` | bool | `false` | 仅记录触发事件的 description，不下发任何 ACL。 |
| `rules_dir` | string | 空 | 可选的用户规则目录（`*.yaml`）。同名文件覆盖内置规则。 |
| `builtin_rules` | bool | `true` | 自动启用全部内置规则。最终生效集合 = 内置规则（启用时）∪ `rules_enabled`。 |
| `rules_enabled` | list | 空 | 额外启用的规则名，与内置规则**合并** —— 启用 `rules_dir` 里的规则就靠它。设 `builtin_rules: false` 时，它改为「从内置规则里挑子集」。名字在内置规则与 `rules_dir` 中解析。`builtin_rules: false` 且此项为空会被拒绝（没规则可跑）。 |
| `sflow.listen` | string | `0.0.0.0:6343` | sFlow v5 UDP 监听地址。 |
| `sample_queue` | int | `65536` | 有界 sample 队列（`0` → 用默认）；处理不过来时丢采样，不增长内存。 |
| `event_queue` | int | `1024` | 有界事件队列（`0` → 用默认）。 |
| `vpp_stats` | block | 无 | 存在 → 轮询 VPP 接口计数器（启用 `vpp.*` 指标）；省略 → 不轮询，且用了 `vpp.*` 的规则会在启动时被拒绝。 |
| `vpp_stats.interval` | duration | `1s` | VPP stats 轮询周期（`0`/省略 → `1s`）。 |
| `vpp_stats.fine` / `medium` / `coarse` | ring | `1s/5m`、`1m/1d`、`1h/30d` | 历史环（与规则 `history` 同一套模型），各含 `resolution` 与 `duration`（某字段为 `0` 用默认）。带 window 的 `vpp.*` term 在能覆盖该窗口的最粗环上聚合；任何环都覆盖不了的窗口会在启动时被拒绝。 |

### 规则文件

规则放在 YAML 文件里，每个文件含 `rules: [ ... ]`（一个或多个规则）。一套精选规则在
编译时内嵌进二进制（仓库的 `rules/` 目录）；运维可在 `rules_dir` 放文件来新增或覆盖。
默认（`builtin_rules: true`）全部内置规则生效；`rules_enabled` 按名字合并进额外规则（例如
`rules_dir` 里的）。设 `builtin_rules: false` 则只跑 `rules_enabled` 列出的子集。规则本身
不需要 `enabled` 字段。

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

`tcp_flags` 过滤 TCP 标志字节：空格/逗号分隔的标志名,前缀 `!` 表示"必须为 0"——如 SYN flood
写 `"syn !ack"`。它要求 `match.proto: tcp`。对身份而言仅是过滤,但默认也会带进下发的 FlowSpec,
使丢弃只针对匹配的标志（如 SYN）,从而保留已建立的连接。可用 `flowspec.tcp_flags` 覆盖下发
（`all` = 不下发标志约束,或写明确的标志）。

`icmp_type` / `icmp_code` 过滤 ICMP/ICMPv6 的 type 与 code（0–255,单值或列表）。它们**只**匹配
`icmp`/`icmpv6` 包——设了任一项的规则永远不匹配非 ICMP 流量。用它把规则限定到特定类型(例如只统计
echo-request flood)。

#### aggregate —— 实例身份

每个命中包都带着所有字段的具体值。这些值组成一个可比较的*描述符*；**描述符相同即同一实例**，
因此 `max_instances` 计的是不同的缓解动作（溢出时按准入草图保留最猛的——见下方 history）。`aggregate` 设定每个
字段的granularity；省略的字段按完整granularity透传。聚合方式按字段类型不同：

| 字段 | 类型 | 形式 | 默认（透传） |
| ---- | ---- | ---- | ------------ |
| `family` | 分类 | 始终是具体 family（不可聚合——IPv4/IPv6 是两套独立 ACL） | 按 family |
| `proto` | 分类 | `exact` \| `all` | `exact` |
| `src`、`dst` | IP 前缀 | `"/N"`（二进制掩码；`/0` 全聚合） | `/32` 或 `/128` |
| `src_port`、`dst_port` | 数字 | `exact` \| `all` \| `"LO-HI"` \| `"N"` | `exact` |
| `icmp_type`、`icmp_code` | 数字（ICMP） | `exact` \| `all` | `exact` |

端口的几种形式：`"22-25"` 把**所有**命中包照抄投影到固定范围 22–25（不校验——适用于 `match`
已限定端口、这里照抄的场景）；`"N"` 是宽度 N 的向下取整分桶,如 `"100"` 时端口 101 落到
**100–199**（分桶为 0–99、100–199……，上界是 N−1 而非 N）；`all` 把所有端口聚合为通配
0–65535。

端口只对 TCP/UDP 存在。没有端口的包(ICMP 等),或 `aggregate.proto` 为 `all` 时的任何包,
都按"端口不适用"处理:端口字段变为通配,既不参与身份、也不下发。所以 ICMP 规则**不需要**把端口
写成 `all`,直接省略即可。编译期唯一的限制是:非通配端口不能和 `aggregate.proto: all` 同时用
(FlowSpec 端口范围需要具体协议)。

`icmp_type`/`icmp_code` 是 ICMP 版的对应物,只对 `icmp`/`icmpv6` 包适用(其余协议恒为通配)。默认
`exact`,所以每个 type/code 是独立实例**且会下发进 drop**——于是某个 ICMPv6 类型(如 echo-request
128)被 flood 时,只丢这个类型,不会误伤邻居发现(NS/NA/RS/RA,类型 133–137,否则会断 IPv6)。设
`icmp_type: all` / `icmp_code: all` 可把对应字段通配(丢往受害者的全部 ICMP)。内置 `icmp-flood-*`
规则用的是 `icmp_type: exact, icmp_code: all`。

#### history —— 每实例的环形缓冲

每个实例最多维护三个固定容量环。`fine` 必填（秒级触发）；`medium`/`coarse` 是可选的更粗 rollup,
用于更长周期上下文。每个环为 `{ resolution, duration }`,且 `duration` 必须是 `resolution`
的整数倍（槽数 = duration ÷ resolution）。内存上界 = `max_instances` × 各环大小,因此分辨率
要能覆盖最长的触发窗口又不过度分配。例如 `fine {1s, 10m}` = 600 槽,`medium {1m, 1d}` = 1440 槽,
`coarse {1h, 7d}` = 168 槽。

##### `max_instances` 这些槽位怎么填(准入)

`max_instances` 限制的是「有几个目标拥有完整环」——但**每个**命中的目标都会被一个 per-rule 的
[HeavyKeeper](https://www.usenix.org/conference/atc18/presentation/gong) 草图(几 KB、固定内存)
廉价观察,估计其近期加权流量。完整实例池只装**估计值最高**的那些目标:

- 池未满时,新目标立即收录。
- 池满后,新目标只有当其草图估计值**超过当前最弱实例**时才被收录,并淘汰那个最弱的。因为草图
  已经观察过两者近期的流量,这是**累积**比较——所以真正更猛的新攻击总能挤掉较轻的,**不会饿死**
  (旧版本用单个样本比较,池满后会冻结整张表)。
- 草图每个 tick 衰减,所以安静下来的目标会淡出、让出位置;持续脉冲的目标不会。

**`rank`(规则字段)。** 默认草图按包速率加权(约 30s 半衰期)。设 `rank: <term名>` 改为按某个
触发项的指标与窗口排名:`bps` 项按**字节**排名(于是 reflection 规则保留的是 **bps** 最高的受害者,
而非 pps 最高的),且草图的衰减半衰期变为该项的 window —— 这样排名估计值在与该项相同的时间跨度上
被平滑(而非生硬的每秒 pps)。被引用的项必须是 `pps`/`bps` 项(`vpp.*` 是接口级,不能用于排名)。
内置 reflection 规则用了 `rank: rate`。

`/status` 端点把每个实例当前的草图估计值作为 `score` 报出(包/秒,或在 bps `rank` 下为字节/秒)。
调大 `max_instances` 扩大池子;代价是 `max_instances` × 环内存 + 一个小的固定草图(按 `max_instances` 定大小)。

#### trigger —— 何时下发

`terms` 是命名窗口聚合；`expr` 是其上的自由布尔表达式；`sustained` 去抖。term 含：

- `metric`：以下之一
  - `pps`（默认）/ `bps` —— 来自本规则历史环的采样流速率。
  - VPP stats 指标(来自 stats 轮询器，见下)。用到其中任一项的规则要求检测器下有
    `vpp_stats:` 块，否则 agent **拒绝启动**，而不是让该项静默读 0。`window` 可选:
    省略则读最新一次轮询值（瞬时）；设置则在 `vpp_stats` 环上做窗口聚合（可配 `offset`
    与 `agg: avg|max`，默认 `avg`；这类速率指标**不支持** `sum`）。

  VPP stats 指标有两个作用域:
  - `vpp.packet_iface.<字段>` —— **该实例的包进来的那个接口**(最近一次的入站接口)。
  - `vpp.total.<字段>` —— **所有** VPP 接口的总和。

  `<字段>` 取值:

  | 字段 | 含义 |
  | --- | --- |
  | `rx_pps` / `tx_pps` | 该接口每秒收 / 发包数 |
  | `rx_bps` / `tx_bps` | 该接口每秒收 / 发比特数 |
  | `sw_drop_pps` | VPP 转发图丢的包/秒（`/if/drops`）——**包含本 agent 自己的 ACL deny** |
  | `hw_drop_pps` | NIC 收包环溢出丢的包/秒（`/if/rx-miss`）——硬件「扛不住」的信号 |

  例如 `vpp.total.rx_bps` 是整机入向比特速率，`vpp.packet_iface.hw_drop_pps`
  是被攻击接口上的网卡级丢包。**没有** `drop_bps`：VPP 的丢包计数器只有包数、没有字节数。
- `window`：聚合的时间跨度（`pps`/`bps` 必填；`vpp.*` 可选，省略则读最新一次轮询值）。
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
`proto`、`src_prefix`、`dst_prefix`、`src_port`、`dst_port`、`icmp_type`、`icmp_code`——均可选,
且**默认取描述符的值**。写模板（`"{{src}}"` 或字面量）可覆盖,写 `all`/`any` 可放宽为通配。描述符
值本身为通配的字段（如聚合为 `/0` 或 `all`）不下发该约束。由于身份是描述符（而非下发规则）,
FlowSpec 可以合法地比身份更宽——例如检测某主机扫 22 端口,但通过把 `proto`/端口聚合为 `all` 来封禁
它的全部流量。

模板变量为描述符字段 `{{family}}`、`{{proto}}`、`{{src}}`、`{{dst}}`、`{{src_port}}`、
`{{dst_port}}`、`{{icmp_type}}`、`{{icmp_code}}`；`description` 还可用 `{{ingress_if}}` 与触发
term 名（如 `{{short}}`）。未知变量在加载时报错。

---

## persist

```yaml
persist: /etc/flowspec-vpp-agent/persist.dump
```

| 字段 | 类型 | 默认值 | 说明 |
| ---- | ---- | ------ | ---- |
| `persist` | string | `<config 同目录>/persist.dump` | **顶层**字段：状态转储（检测器规则 history + VPP stats 环）的路径，退出时写入、启动时载入，使快速重启后从近期历史恢复检测。省略时默认取配置文件同目录下的 `persist.dump`；填明确路径可改位置。仅在检测器运行时使用。 |

载入时，只有仍然匹配的条目才会恢复 history。出现以下情况会**跳过**该条目：

- 规则被**删除**或**改名**（不存在同名规则）；或
- 规则**定义改变**——整条规则配置（match、aggregate、history 尺寸**含 `max_instances`**、trigger、flowspec、rank、description）被哈希成一个指纹，指纹一变，该规则就不载入任何旧 history；或
- 某个 VPP-stats 接口的**环形状变了**（resolution/duration）。

这是有意为之：定义变了之后，旧 history 的含义可能已经不同，所以改过的规则从零开始。准入草图从不持久化（一个半衰期内自行重建）。

---

## log

日志会分发到一个或多个**输出模块（sink）**，每个模块按**等级（level）**与**范围
（scope）**独立过滤。整段 `log` 省略时保持默认：stderr、`info`、范围 `all`、`text`。

```yaml
log:
  stderr:                       # 默认模块，始终启用（省略 => info/all/text）
    level: info
    scope: all
    format: text
  telegram:                     # 可选；写了即启用
    bot_token: "123456:ABC-DEF"
    chat_id: "-1001234567890"
    level: info
    scope: [detector, acl]      # 只要检测器事件 + ACL 变化
    format: text
```

### 范围（scope）

每条日志带一个**范围**（由发出它的子系统决定）。模块的 `scope` 选择接收哪些：`all`、
`none`（关闭该模块）、单个范围，或一个列表。

| 范围 | 覆盖 |
| --- | --- |
| `core` | 启动/退出、配置、HTTP 端点、状态载入/保存 |
| `bgp` | BGP speaker 与各 peer 会话 |
| `acl` | FlowSpec 规则 **下发 / 更新 / 撤销**（即期望 ACL 集合发生变化） |
| `vpp` | VPP 连接/重连、ACL 挂载/清理、底层 replace |
| `detector` | 检测器事件（announce/expire）、sFlow、VPP-stats 轮询、租约 |

所以 `scope: [detector, acl]` 只投递检测器事件与 FlowSpec 规则变化，**不含** VPP
连接/挂载的噪声 —— 适合做告警模块。

### stderr

| 字段 | 类型 | 默认值 | 说明 |
| -------- | ------ | ------- | ---- |
| `level` | string | `info` | `debug` / `info` / `warn` / `error`。`debug` 会打印每条规则的去重细节。 |
| `scope` | scope | `all` | `all` / `none` / 单个范围 / 列表。 |
| `format` | string | `text` | `text` 或 `json`。容器/采集场景建议 `json`。 |

### telegram

写了即启用。日志被格式化（text/json）、**批量**通过 Telegram Bot API 投递到聊天。该模块
完全异步：从不阻塞日志路径；其有界队列溢出时丢弃日志（下一条消息里报告
`[N log lines dropped]`），而不是拖慢 agent。

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `bot_token` | string | — | **必填。** BotFather 给的 token。 |
| `chat_id` | string | — | **必填。** 目标聊天/频道 id。 |
| `level` | string | `info` | 同 stderr。 |
| `scope` | scope | `all` | 同 stderr。 |
| `format` | string | `text` | 同 stderr。 |

> **安全：** `bot_token` 是凭据，Telegram 是外部服务 —— 消息（含日志字段里的任何数据）会
> 离开本机，并可能被 Telegram 留存。请勿把 token 写进共享/提交的配置，并把该模块的范围收窄到
> 你确实需要远程看到的内容。

默认日志写到 **stderr（标准错误）**。被忽略的规则会在 `warn` 级别记录，包含 `reason`、
`detail`、`family`、`peer`、`original_flowspec` 等字段，便于排查。

> 命令行覆盖配置路径：`--config` / `-c`。

