# IPv6 出站代理程序 (ipv6-proxy)

轻量级 IPv6 出站代理，在 **dummy 虚拟接口 (`v6test0`)** 上管理多个 IPv6 测试地址，通过 socket `bind()` 指定出口 IPv6（包仍从真实 WAN 出站）。
支持 HTTP CONNECT 代理、SOCKS5 代理、地址池管理、分阶段连通性诊断、REST API。

**零外部依赖**（仅 Go 标准库），静态编译，适合 OpenWrt ARM64，低 CPU/低内存。

> 本机路由器/运营商网络的实证连通性调研（SLAAC vs PD、DNS、Cloudflare IPv6 部分可达、opencode.ai 绕过等）见 [`RESEARCH.md`](./RESEARCH.md)。

---

## 一、文件清单

```
ipv6-proxy/
├── main.go              # 全部逻辑（单文件，零依赖）
├── go.mod               # 模块定义
├── config.json          # 配置示例
├── ipv6-proxy.init      # OpenWrt procd 开机脚本
└── README.md            # 本文档
```

---

## 二、交叉编译（开发机，linux/amd64 亦可）

```bash
# 需要 Go 1.21+
export PATH=$HOME/go-sdk/go/bin:$PATH   # 或你的 go 路径

cd ipv6-proxy
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -ldflags="-s -w" -o ipv6-proxy-arm64 main.go

# 验证
file ipv6-proxy-arm64
# → ELF 64-bit LSB executable, ARM aarch64, statically linked
```

其他架构：
```bash
GOARCH=arm     # 32 位 ARM (armv7)
GOARCH=mipsle  # 极路由等
GOARCH=amd64   # x86_64 软路由
```

---

## 三、安装到 OpenWrt

```bash
# 1. 上传二进制（用 sshpass / scp / winscp 均可）
scp ipv6-proxy-arm64 root@192.168.100.1:/tmp/ipv6-proxy

# 2. 路由器上执行
ssh root@192.168.100.1
mkdir -p /etc/ipv6-proxy
cp /tmp/ipv6-proxy /usr/bin/ipv6-proxy
chmod +x /usr/bin/ipv6-proxy
cp /path/to/config.json /etc/ipv6-proxy/config.json

# 3. 安装 procd 开机脚本
cp /path/to/ipv6-proxy.init /etc/init.d/ipv6-proxy
chmod +x /etc/init.d/ipv6-proxy
/etc/init.d/ipv6-proxy enable
```

---

## 四、配置文件示例 (config.json)

```json
{
  "proxy_addr": "[::]:8080",
  "api_addr": "[::]:9191",
  "prefix": "2409:8a62:578:d600::/60",
  "subnet_count": 4,
  "source_mode": "slaac",
  "slaac_pool_size": 4,
  "failure_threshold": 3,
  "health_interval_sec": 60,
  "connect_timeout_sec": 5,
  "selection_mode": "round-robin",
  "max_retries": 5,
  "dummy_iface": "v6test0",
  "dns_server": "2606:4700:4700::1111",
  "test_target": "2606:4700:4700::1111",
  "hosts": {}
}
```

字段说明：
| 字段 | 说明 |
|------|------|
| `proxy_addr` | HTTP+SOCKS5 代理监听地址（同一端口自动识别协议） |
| `api_addr` | 管理 API 地址 |
| `prefix` | IPv6 前缀（PD 或 WAN `/64`），建议写 `/60`。留空则自动探测（`default from` 源策略路由的 PD 前缀 → WAN `/64`） |
| `subnet_count` | `source_mode=pool` 时，从 PD 内取多少个 `/64` 子网各生成一个测试地址（默认 4 → d600/d601/d602/d603） |
| `slaac_pool_size` | `source_mode=slaac` 时，在 WAN 原生 `/64` 内生成多少个固定 `/128` 源地址（默认 4） |
| `failure_threshold` | `source_mode=slaac` 时，连续路由/bind 失败多少次才把该地址标记 `failed` 移出调度（默认 3） |
| `health_interval_sec` | 定期健康检查间隔 |
| `connect_timeout_sec` | 单连接超时（同时用作数据阶段上限，防止运营商黑洞连接挂死） |
| `max_retries` | 出栈失败时的重试次数。**仅在 `source_mode=ephemeral` 下生效**，每次重试换一个全新源地址 |
| `selection_mode` | `round-robin` / `random` / `manual`（池内选择算法，`pool` 与 `slaac` 生效）。`manual` 不自动轮换：一直用当前钉住的源地址，直到通过 `/api/select` 切换（钉到指定 IP 或切到下一个） |
| `source_mode` | `pool`（默认，从 dummy 上的 PD 预置地址池轮换）/ `ephemeral`（**每个出栈连接临时生成一个全新 PD 源地址，用完即弃**）/ `slaac`（**在 WAN 原生 `/64` 内生成固定 `/128` 源地址池，直接加在 `pppoe-wan` 上，最稳定**） |
| `dummy_iface` | 承载测试地址的 dummy 接口名（默认 `v6test0`，不存在则创建，退出时若由本程序创建则删除） |
| `dns_server` | 域名解析的 DNS（默认 `2606:4700:4700::1111`，纯 IPv6 代理只认 AAAA；可填 `2400:3200::1` 等）。未配置则回退系统解析器，详见 RESEARCH |
| `test_target` | 路由检查 / TCP / TLS 测试目标（默认 `2606:4700:4700::1111`） |
| `hosts` | 静态映射（覆盖 DNS，最高优先级）。键为域名（自动忽略 `:端口`、大小写不敏感）；值可以是**合法 IPv6 字面量**，也可以是**另一个域名（别名）**。值为域名时，在请求时解析它的 AAAA 并直接返回该 IP（支持 `opencode.ai → ssl.xxx.xyz` 这类域名→域名映射，解析结果同样走 AAAA 缓存）。IPv4 字面量会在加载时被跳过并告警（本代理为纯 IPv6 出栈）。适用于：给已知可达的主机钉死固定 IPv6，或把被墙/错误 AAAA 的域名别名到一个可达的隧道域名。例：`"hosts": {"example.com": "2001:db8::1"}` 或 `"hosts": {"opencode.ai": "ssl46.190564326.xyz"}` |

**前缀优先级**：`prefix` 显式指定 > 自动探测 PD > 自动探测 WAN /64。（`source_mode=slaac` 时直接自动探测 WAN 的全局 SLAAC `/64`，忽略 `prefix` 设置）

地址生成：对每个选中的 `/64` 子网（PD 内第 i 个子网 = 第 4 段低 4 位 = `d60i`），在该 `/64` 内随机选一个 `/128` 作为测试地址，加在 `dummy_iface` 上。

---

## 五、启动方式

### 手动
```bash
/usr/bin/ipv6-proxy /etc/ipv6-proxy/config.json
```

### procd（开机自启）
```bash
/etc/init.d/ipv6-proxy start
/etc/init.d/ipv6-proxy stop
/etc/init.d/ipv6-proxy restart
logread | grep ipv6-proxy    # 查看日志
```

### systemd（x86_64 软路由 / 普通 Linux）
```bash
cat > /etc/systemd/system/ipv6-proxy.service <<'EOF'
[Unit]
Description=IPv6 Outbound Proxy
After=network.target

[Service]
ExecStart=/usr/bin/ipv6-proxy /etc/ipv6-proxy/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ipv6-proxy
```

---

## 六、API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/status` | 总体状态（WAN/虚拟接口、前缀、存活数、DNS/测试目标、策略表） |
| GET | `/api/ips` | 地址池详细诊断列表（见下） |
| GET | `/api/config` | 当前配置 |
| GET | `/api/test?ip=...` | 对指定 IPv6 做完整分阶段测试，返回详细结果 |
| GET | `/api/add?ip=...` | 手动添加 IPv6 到池并异步测试 |
| GET | `/api/generate?count=5` | 在 PD 内随机生成 N 个 IPv6 源地址，加入池并并发测试，返回各自可用性 |
| GET | `/api/remove?ip=...` | 手动移除 IPv6 |
| GET | `/api/select` | 查看当前选择状态（`selection_mode` / `pinned`）。可用查询参数：**`?mode=manual\|round-robin\|random`** 运行时切换选择算法；**`?ip=...`** 钉死某个源 IPv6（须在池内）；**`?next`** 在 `manual` 模式下切到下一个存活地址 |
| GET | `/api/logs` | 返回内存中最近日志（`?lines=N` 限制条数，默认 200），便于不登机器排查 |

`/api/ips` 与 `/api/test` 均返回每个地址的完整诊断：
```json
{
  "ip": "2409:8a62:578:d600::1",
  "subnet": "2409:8a62:578:d600::/64",
  "interface": "v6test0",
  "status": "alive | dead | checking",
  "address_added": true,
  "route_check": { "success": true, "interface": "pppoe-wan", "output": "..." },
  "policy_routed": false,
  "bind": true,
  "tcp":   { "success": true,  "error": "" },
  "tls":   { "success": false, "error": "i/o timeout" },
  "https": { "success": false, "error": "" },
  "public_ip": "",
  "failure_stage": "tls_failed"
}
```

`failure_stage` 取值：`address_add_failed` / `route_failed` / `bind_failed` / `tcp_timeout` / `tcp_failed` / `tls_failed` / `https_failed` / `public_ip_mismatch` / `success`。

分阶段诊断顺序（每个 IP 独立）：
1. **address_added** — 地址是否成功加到 `v6test0`
2. **bind** — 能否以该地址 `bind()`（UDP）
3. **route_check** — `ip -6 route get TARGET from TEST_IP` 是否命中真实 WAN 出口；若未命中则自动加一条最小影响策略路由（`table 100`，`from /128`），再复测
4. **tcp** — 以该地址为源建立到 `test_target:80` 的 TCP 连接
5. **tls** — `test_target:443` 的 TLS 握手
6. **https** — 经该地址访问 `https://api64.ipify.org`，解析器 Bind 到测试源地址
7. **public_ip** — 比对回显公网 IP 是否等于测试地址

示例：
```bash
curl http://[::1]:9191/api/status
curl http://[::1]:9191/api/ips
curl http://[::1]:9191/api/add?ip=2409:8a62:578:d600::100
curl http://[::1]:9191/api/generate?count=5
curl http://[::1]:9191/api/remove?ip=2409:8a62:578:d600::100
curl http://[::1]:9191/api/test?ip=2409:8a62:578:d600::100
```

---

## 七、代理使用

### HTTP 代理（指定出口 IPv6）
```bash
curl -x http://[::1]:8080 \
     -H "X-Source-IPv6: 2409:8a62:578:d600::5" \
     https://api.ipify.org
```

不指定 `X-Source-IPv6` 时按 `selection_mode`（轮询/随机/`manual`）从存活池选；`manual` 模式一直用当前钉住的地址，直到通过 `/api/select` 切换。

### SOCKS5 代理（用户名即出口 IPv6）
```bash
curl -x socks5://2409:8a62:578:d600::5:@[::1]:8080 https://api.ipify.org
#       ↑ 用户名=出口 IPv6，密码任意/空
```

不使用用户名认证时按 `selection_mode` 自动选（`manual` 模式需先用 `/api/select` 钉一个地址）。

---

## 八、验证每个 IPv6 真正作为 source IP 出站

### 方法 A：在路由器上抓包
```bash
tcpdump -i pppoe-wan -n 'ip6 and host 2606:4700:4700::1111' -ttt
# 另发请求：
curl -x http://[::1]:8080 -H "X-Source-IPv6: 2409:8a62:578:d600::5" \
     http://[2606:4700:4700::1111]/
# 应看到：IP6 2409:8a62:578:d600::5.XXX > 2606:4700:4700::1111.80: Flags [S]
# 注意：测试地址在 v6test0 上，但包从 pppoe-wan 出站，src 即该地址
```

### 方法 B：用回显服务
```bash
curl -x http://[::1]:8080 -H "X-Source-IPv6: 2409:8a62:578:d600::5" \
     http://ipv6.icanhazip.com/
# 返回应等于你指定的源 IPv6（需路由器 DNS 支持 AAAA）
```

### 方法 C：API 健康检查日志
```bash
logread | grep HEALTH
# [HEALTH] 2409:8a62:578:d600::5 is alive
```

---

## 九、处理 IPv6 地址失效

程序自动处理：
1. 启动时添加所有地址并立即做连通性测试。
2. 每 `health_interval_sec` 秒重新测试。
3. 测试失败 → 标记 `dead`，代理不再选用。
4. 测试恢复 → 标记 `alive`，重新入池。
5. `dead` 地址**保留在接口上**（不主动删除，避免抖动），仅从调度排除。

手动干预：
```bash
curl http://[::1]:9191/api/remove?ip=2409:8a62:578:d600::5   # 彻底移除
curl http://[::1]:9191/api/add?ip=2409:8a62:578:d600::5     # 重新加回
```

---

## 十、优雅删除程序创建的资源

程序在收到 `SIGTERM`/`SIGINT` 时执行 `CleanupAddedAddresses()`：
1. 删除 `v6test0` 上由它添加的所有 `/128` 测试地址；
2. 删除为每个地址添加的策略路由规则（`from /128 table 100`）与 `table 100` 默认路由；
3. 若 `v6test0` 是由本程序新建的，则删除该 dummy 接口。

```bash
# procd
/etc/init.d/ipv6-proxy stop
# 或手动
kill -TERM $(pidof ipv6-proxy)

# 验证已清理
ip -6 addr show dev v6test0 | grep '578:d600'   # 应为空（接口可能已被删除）
ip -6 rule show | grep 'table 100'              # 应为空
ip link show v6test0                            # 若原本不存在，应已删除
```

> 注意：若程序异常崩溃（kill -9），资源可能残留。手动清理：
> ```bash
> for i in $(seq 1 20); do
>   ip -6 addr del 2409:8a62:578:d600::$(printf '%x' $i)/128 dev v6test0 2>/dev/null
> done
> ip -6 rule flush table 100 2>/dev/null
> ip link del v6test0 2>/dev/null
> ```

---

## 十一、重要说明（关于运营商限制）

1. **程序会创建一个 dummy 虚拟接口 `v6test0`**（无 MAC、无链路），仅用于承载测试地址；包仍从真实 WAN 出站。`v6test0` 若原本已存在且为 dummy 则复用，否则由本程序创建并在退出时删除。
2. **程序默认不修改默认 IPv6 路由**。仅当 `ip -6 route get TARGET from TEST_IP` 未命中真实 WAN 出口时，才加一条最小影响的策略路由（`table 100`：`from TEST_IP/128 table 100` + 该表默认路由），不触碰主路由表。
3. **程序不能凭空创造可路由的公网 IPv6 前缀**。能否多用地址完全取决于运营商是否把前缀路由回你。
4. `slaac` 在 WAN `/64` 内生成固定源池，`pool` 从 PD 前缀生成；前缀须由运营商路由才可用，失败阶段见 `failure_stage`。
5. 若有 `/56`、`/60` PD 且已路由，把 `prefix` 设为该 PD 即可规模使用。

---

## 十二、排查清单

```bash
# 1. WAN 接口
ip -6 route show default

# 2. 探测到的前缀
curl http://[::1]:9191/api/status | grep prefix

# 3. 地址是否加上
ip -6 addr show dev v6test0 | grep '你的前缀'

# 4. 手动测一个地址
curl --interface 2409:8a62:578:d600::5 -v http://[2606:4700:4700::1111]/

# 5. 抓包看是否回程
tcpdump -i pppoe-wan -n 'ip6 and host 2606:4700:4700::1111'
```

若 SYN 发出但无 SYN-ACK → 运营商未路由该源地址（见第十二节）。
