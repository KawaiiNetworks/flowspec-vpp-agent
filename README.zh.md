# flowspec-vpp-agent

> 🌐 [English](README.md) · **中文**

一个控制面适配层：消费来自一个或多个 peer 的 **BGP FlowSpec**（RFC 8955/8956），通过标准 VPP
ACL 插件（`acl_add_replace`，走 GoVPP binary API）下发等价的 **VPP ACL**。

它是一个保守的翻译器：只下发能与 VPP ACL 条目**等价**的规则。无法精确表达的规则一律忽略
（绝不近似），并暴露为 Prometheus 指标，让运维能察觉——对一个 DDoS 缓解工具来说，一条被静默
丢弃的规则就意味着一次未被缓解的攻击。

详细文档：[部署与使用教程](docs/zh/tutorial.md) 与 [配置文件详解](docs/zh/configuration.md)。

## 功能

- **地址族：** IPv4 与 IPv6 FlowSpec，支持 announce 与 withdraw。
- **匹配组件：** dst/src prefix、protocol/next-header、dst/src port、TCP flags、ICMP
  type/code。每项必须能归约为单一精确值或单一连续区间——`!=`、不连续 OR 集合、VPP 期望精确值
  处的区间、IPv6 prefix `offset != 0`、fragment、generic port、packet-length、DSCP、flow-label
  全部拒绝。
- **动作：** 仅 drop（`traffic-rate 0` / `discard`）→ VPP `deny`。限速、redirect、marking、
  sample 等一律忽略。
- **多会话：** 多个 BGP peer 的规则按引用计数合并进同一组 Managed ACL（IPv4 一个、IPv6 一个）。
  不同会话的相同规则只生成一条 entry；最后一个持有者撤销时才删除；会话断开等价撤销其全部规则。
- **应用：** 两个 Managed ACL 默认挂到全部数据面接口的入向（ingress）；可配置。
- **可观测性：** `flowspec_rules_ignored_total{reason,family,peer}`、
  `flowspec_rules_applied_total{family,peer}`、`flowspec_acl_entries{family}`。

## 架构

```
bgp（多会话, GoBGP) ──Update{session,op,rule}──▶ manager
  manager: translate → ok ? 引用计数 + 调谐 : ignored(metric + log)
  vpp: acl_add_replace / 把 Managed ACL 挂到全部数据面接口（ingress）
```

| 包                  | 职责                                                          |
| ------------------- | ------------------------------------------------------------- |
| `internal/flowspec` | 内部 FlowSpec 模型 + GoBGP NLRI/属性解析。                    |
| `internal/translate`| 纯函数、无状态 `Rule → vpp.ACLRule`；全部支持性检查；测试最密。 |
| `internal/manager`  | 唯一有状态的组件：每条规则的引用计数 + 调谐。                  |
| `internal/vpp`      | GoVPP 后端：连接+退避重连、`acl_add_replace`、接口挂载。       |
| `internal/bgp`      | 内嵌 GoBGP speaker；产出与来源无关的 `Update` 事件。           |
| `internal/config`   | YAML 配置 + 校验。                                            |
| `internal/metrics`  | Prometheus 指标。                                            |

VPP ACL/接口的 binary API 绑定直接来自 `go.fd.io/govpp` 模块（自带生成绑定），因此本仓库**没有**
`binapi/` 生成步骤。

## 构建与测试

```sh
make build       # 静态二进制 -> bin/flowspec-vpp-agent
make test        # 单元 + 集成测试
make vet
```

> 本仓库在 NixOS 上开发，若 `go` 不在 PATH，用 `nix-shell -p go --run 'make build'`。

## 运行

见 [deploy/](deploy/)：`compose.yaml`、`config.example.yaml`、`Dockerfile`。compose 把宿主机的
`./config` 目录只读挂载到 `/etc/flowspec-vpp-agent`，agent 读取其中的 `config.yaml`。快速开始：

```sh
mkdir -p config
cp deploy/config.example.yaml config/config.yaml   # 修改 peers / router_id
docker compose -f deploy/compose.yaml up -d
```

VPP 必须持有 `/run/vpp/api.sock`；agent 会退避重连，VPP 未就绪或重启时不会崩溃。
