# 部署与使用教程

> 🌐 [English](../en/tutorial.md) · **中文**

本教程介绍如何把 `flowspec-vpp-agent` 跑起来：从准备 VPP、构建镜像、编写配置，到下发第一条
FlowSpec 规则并验证生效。配置项的逐字段说明见 [configuration.md](configuration.md)。

---

## 1. 它做什么

agent 是一个**控制面适配层**：

```
FlowSpec peer(s) ──BGP──▶ flowspec-vpp-agent ──VPP binary API──▶ VPP ACL
```

它消费标准 BGP FlowSpec（RFC 8955/8956），把**能等价映射**的规则翻译成 VPP ACL `deny` 条目，
挂到全部数据面接口的入向。无法精确表达的规则一律忽略（绝不近似下发），并通过 metric 暴露，
以便运维及时发现。

设计要点：

- 支持 IPv4 / IPv6，announce 与 withdraw。
- 仅 drop 动作（`traffic-rate 0` / `discard`）。
- 多会话：多个 peer 的规则按引用计数合并进同一组 Managed ACL（IPv4 一个、IPv6 一个），
  相同规则只生成一条 entry，最后一个持有者撤销时才删除。
- 仅依赖标准 VPP ACL 插件，不假设有 FastACL 引擎。

---

## 2. 前置条件

- 一台运行 **VPP** 的主机，已加载标准 **ACL 插件**，且其 binary API socket 位于
  `/run/vpp/api.sock`（root 或 vpp 组持有）。
- 采用 **inline / bump-in-the-wire** 部署：流量物理穿过 VPP 的数据面接口，挂全部数据口入向
  即覆盖全部流量。
- 一个或多个会发送 FlowSpec 的 BGP peer（例如 FastNetMon 的 FlowSpec exporter）。
- 部署方式二选一：docker / podman compose（推荐），或直接跑二进制。

---

## 3. 获取镜像 / 构建

### 3.1 使用已发布镜像

CI 会把镜像推到 `kawaiinetworks/flowspec-vpp-agent`，compose 默认引用 `:main` 标签。

### 3.2 本地构建二进制

CGO 关闭的静态二进制：

```sh
make build        # 产出 bin/flowspec-vpp-agent
make test         # 单元 + 集成测试
```

> 本仓库在 NixOS 上开发，若 `go` 不在 PATH，用 `nix-shell -p go --run 'make build'`。

### 3.3 本地构建镜像

```sh
make docker       # 构建 kawaiinetworks/flowspec-vpp-agent:main
```

---

## 4. 编写配置

compose 把宿主机 `./config` 目录挂到容器 `/etc/flowspec-vpp-agent`，agent 读取其中的
`config.yaml`：

```sh
mkdir -p config
cp deploy/config.example.yaml config/config.yaml
```

按需修改 `config/config.yaml`，最常改的是 `bgp.router_id`、`bgp.asn` 和 `bgp.peers`：

```yaml
bgp:
  listen: "0.0.0.0:10179"     # 默认 10179，避开原生 BGP 守护程序
  router_id: "192.0.2.1"
  asn: 65000
  peers:
    - address: "198.51.100.1" # FlowSpec exporter
      peer_asn: 65001
      passive: true
```

每个字段的含义见 [configuration.md](configuration.md)。

---

## 5. 用 compose 部署

部署文件见 [../../deploy/compose.yaml](../../deploy/compose.yaml)。关键点：

- `volumes` 挂载 `/run/vpp`（一次覆盖 api.sock 与 stats.sock）和 `./config` 配置目录。
- `network_mode: host`：BGP 监听端口直接落在宿主机；socket 仍走挂载，无需容器网络。
- `user: "0:0"`：以 root 访问 root 持有的 api.sock。
- `healthcheck` 调用 `flowspec-vpp-agent healthcheck`，请求本机 `/healthz`。

启动：

```sh
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml logs -f
```

### podman + SELinux

挂载用 `:z`（共享标签），**不要用 `:Z`**（私有标签会重贴 `/run/vpp`，可能让宿主机 VPP 自己
访问不了）。更稳妥可对该容器 `security_opt: ["label=disable"]`，不去动 `/run/vpp` 的标签。
rootless podman 下 uid 映射会让访问 socket 困难，建议 rootful / root 运行。

### bridge 网络（可选）

若不想用 host 网络，去掉 `network_mode: host`，改为发布端口：

```yaml
ports:
  - "10179:10179"
```

`/run/vpp` 挂载保持不变。

---

## 6. 直接跑二进制（非容器）

```sh
sudo ./bin/flowspec-vpp-agent -config /path/to/config.yaml
```

agent 会以 root 访问 VPP socket；socket 未就绪或 VPP 重启时退避重连。可配合任意进程管理器
（systemd / supervisor 等）守护，并设置失败自动重启。

---

## 7. 验证生效

### 7.1 健康检查与指标

```sh
curl -s http://127.0.0.1:9469/healthz          # 应返回 ok
curl -s http://127.0.0.1:9469/metrics | grep flowspec_
```

关注三个指标：

- `flowspec_rules_applied_total{family,peer}` —— 成功下发的规则数。
- `flowspec_rules_ignored_total{reason,family,peer}` —— 被忽略的规则数（按原因/族/peer 区分）。
- `flowspec_acl_entries{family}` —— 当前每个 Managed ACL 的 entry 数。

### 7.2 在 VPP 侧查看

```sh
vppctl show acl-plugin acl                      # 查看 Managed ACL 及其规则
vppctl show acl-plugin interface                # 查看接口挂载情况（入向）
```

下发一条「dst 203.0.113.10/32, udp, dport 443, traffic-rate 0」后，应能在 IPv4 Managed ACL
中看到一条 `deny`，dst 为 `203.0.113.10/32`、proto 17、dst port `443-443`、src `0.0.0.0/0`、
src port `0-65535`。withdraw 后该条目消失（若无其他会话仍持有）。

---

## 8. 规则支持范围（速查）

**支持的 match**：dst/src prefix、protocol/next-header（精确）、dst/src port（可归约为单一连续
区间，含 `>`/`<`/`>=`/`<=`）、tcp flags（`syn`、`syn,!ack` 等简单组合）、icmp type/code（精确）。

**会被忽略的规则**（记 warning + ignored metric，不下发）：

- 动作非 drop：`traffic-rate > 0`、redirect、marking、sample 等。
- 端口 `!=`、不连续端口集合、复杂 OR 表达式。
- protocol 的非等值 / 多协议 OR。
- tcp flags 出现在非 TCP 协议上；复杂 bitmask（match any/none of）。
- generic port、packet length、dscp、flow label。
- fragment（标准 ACL 插件无对应字段；不能丢弃 fragment 条件后继续下发其余 match）。
- IPv6 prefix `offset != 0`（无法等价映射）。

完整规则见 [configuration.md](configuration.md) 的 metrics 段与各动作/匹配说明。

---

## 9. 常见问题

| 现象 | 排查方向 |
| ---- | -------- |
| 启动后一直 "connecting to VPP" | VPP 未起或 `vpp.socket` 路径不对；确认 `/run/vpp/api.sock` 存在且容器已挂载。agent 不会因此崩溃，会持续重连。 |
| 容器无法访问 socket | 用 `user: "0:0"`；podman+SELinux 用 `:z` 或 `security_opt: label=disable`；避免 rootless。 |
| 规则没生效 | 查 `flowspec_rules_ignored_total` 是否在涨、看 `warn` 日志里的 `reason`/`detail`；确认 peer 已 `ESTABLISHED`。 |
| VPP 重启后规则丢失 | agent 会在重连后重建 Managed ACL 并重新下发全部规则（resync），无需手动干预。 |
| 多个会话下发同一规则 | 只会生成一条 entry；某会话撤销或断开后，只要还有别的会话持有，entry 就保留。 |
