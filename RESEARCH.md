# 网络调研记录 / Research Notes

> 本机路由器 + 运营商下为 `ipv6-proxy` 做的实证发现（lab notebook）。用法见 [`README.md`](./README.md)。

## 环境
- 路由器 OpenWrt 24.10.5 aarch64，WAN `pppoe-wan`，运营商**中国移动**。
- WAN SLAAC：`2409:8a62:507:a2f0::/64`（当前）；PD `2409:8a62:572:9b80::/60`（ISP 下发，lan 已分配）。
- IPv4：CGNAT `100.64.162.87`（无公网 IPv4，但 IPv4 出栈可用）。
- `pppoe-wan` 另有静态 `2409:8a62:507:a2f0::101/64`（DNS 查询默认源）。

## 网络概念分析

### 1. IPv6 源地址选择 (RFC 6724)
- 内核默认按 RFC 6724 自动选源地址（同前缀优先、scope 优先等）。
- **`bind()` 可以覆盖内核选择**：`net.Dialer.LocalAddr = &net.TCPAddr{IP: x}` 后，出去的包 `src` 就是 `x`。
- 本程序核心机制就是：每个出站连接 `bind()` 到指定 IPv6。

### 2. NDP（邻居发现）
- IPv6 用 NDP（ICMPv6）替代 ARP。新增地址会触发 DAD（重复地址检测）。
- 在 PPPoE 这种点对点链路上没有传统 NDP 邻居解析；包直接发给对端网关。
- 内核会在接口上添加地址并响应 NDP NS（如果链路支持），**不影响默认路由**。

### 3. Prefix Delegation (PD)
- 运营商通过 DHCPv6-PD 下发前缀（如 `/56`、`/60`、`/64`）。
- **运营商只路由它分配的前缀**。在未被路由的前缀里造地址 = 不出站（无回程）。
- 本路由器当前路由表（示例）：
  ```
  default from 2409:8a62:507:a2f0::/64  via ... dev pppoe-wan   # WAN 自身 /64
  default from 2409:8a62:572:9b80::/60  via ... dev pppoe-wan   # PD 前缀（源策略路由）
  ```
  第二条 `default from ... /60` 是**源策略路由**：源地址属于该 /60 时走默认路由。

### 4. socket bind 与路由
```
bind(2409:8a62:572:9b80::1) → connect(target)
```
- 出去的包：`src=2409:8a62:572:9b80::1, dst=target`
- 若运营商路由了该 /60，回程正常；否则 SYN 发出去但无 SYN-ACK。

## 根因更正：`wan6.ifname` 绑错
- 原配置 `wan6.ifname='eth1'` 指向物理以太口，DHCPv6 在物理口空等，PD 始终未下发（或下发到错误链路）。
- 改为 `wan6.ifname='@wan'` 后 DHCPv6 跑在 `pppoe-wan` 隧道内，PD 立即下发为 `2409:8a62:572:9b80::/60`，lan 自动分配，无需再改。
- 此前 PD 相关结论（`578:d600::/60`、`首连放行/复用即封`、`ephemeral` 必要）均为**误判**：一是自动探测把 WAN `/64` 当 PD 取用，二是探测目标 `2606:4700:4700::1111` 本身不稳。

## SLAAC vs PD（更正后实测）
- 显式 `prefix: 2409:8a62:572:9b80::/60` + `test_target: 2606:4700:3035::ac43:afac`（可达 CF 前缀）后：
  - 池 4/4 `alive`（`tls_failed` 仅诊断），`pppoe-wan` / `v6test0` 均稳定；
  - 代理轮询 10 次 `ipv6.ddnspod.com` 10/10 200，10 次 `v6.66666.host:66` 10/10 200，5 次 `opencode.ai` 5/5 200；
  - 同一 PD IP 对 `2400:3200::1:53` 10 次复用 10/10 成功，对 `2606:4700:3035::ac43:afac:80` 复用亦稳定。
- 结论：**PD 与 SLAAC 当前均稳定可用**；`ephemeral`（每连接新 IP）为历史 workaround，已冗余但保留不影响（仅 `source_mode=ephemeral` 时触发）。

## DNS
- `1.1.1.1`（CF IPv4）经 CGNAT **可达且返回 AAAA**。
- `2400:3200::1`（阿里 IPv6）稳定，作默认。
- `2606:4700:4700::1111`（CF IPv6）间歇不可达。
- 传输：让 Go 自选（先 UDP，截断再 TCP），仅重写目标到配置 DNS；解析策略=配置 DNS→系统，仅留 AAAA。
- 静态 `hosts`：最高优先级，绕过 DNS。

## Cloudflare IPv6 部分可达（前缀相关，非整段被封）
| 前缀 | 站点 | 可达 |
|------|------|------|
| 2606:4700:78:: | opencode.ai | ❌ 不可达 |
| 2606:4700:3035:: | ssl46.190564326.xyz | ✅ 0% 丢包 |
| 2606:4700:3037:: | ifconfig.co | ✅ 偶发丢包 |
| 2606:4700:4700::6810 | ipv6.icanhazip.com | 偶发 |
| 2606:4700:4700::1111 | CF DNS | 间歇 |

## opencode.ai 绕过
- 其 AAAA 落在被封前缀 `2606:4700:78::` → 超时。
- 绕过：静态映射 `opencode.ai → ssl46.190564326.xyz`（解析到 `2606:4700:3035::ac43:afac` 可达）。两者同处 Cloudflare anycast，连该 IP 带 `SNI=opencode.ai` 即得正确内容 → 实测 200。
- 风险：钉死域名别名，若 ssl46 AAAA 变化需重解。

## 纯 IPv4 站点（无 AAAA → 需 NAT64）
`opencode.oci.213470.xyz`（A 117.139.140.63 / 43.174.246.104）、`www.daji.it:6`、`6.ipw.cn` 不可达；`www.taobao.com` 可达但 403。

## 站点实测
| 站点 | 结果 |
|------|------|
| ipv6.icanhazip.com / ipv6.ddnspod.com / v6.66666.host:66 / ifconfig.co | 200 |
| opencode.ai | 200（经静态映射） |
| speed.neu6.edu.cn | 超时（教育网 2001:da8:9000::66 被运营商不可达） |
| opencode.oci.213470.xyz | 失败（纯 IPv4） |

## 运维 & 待决
- 编译：`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build`。重启用 SIGTERM 清 /128；`kill -9` 留僵尸需手清。
- 偶发整体抖动（仅阿里 DNS 前缀可达、web IPv6 全超时）属运营商侧，非代理问题。
- 纯 IPv4 站点需 NAT64+DNS64（范围外）；静态映射可扩展为“解析某域名取 AAAA”。
