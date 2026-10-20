# IPv6 出站代理

轻量 Go 代理，一行命令让多个 IPv6 轮流出站。家庭 `PD` 与 `OCI` 双场景。

## 编译
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o ipv6-proxy-arm64 .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ipv6-proxy-amd64 .
# Release 自动打 tag latest，产出 ipv6-proxy-arm64.tar.gz / amd64.tar.gz（含 config）
```

## 配置
`config.json` 家庭：`source_mode=pool` 自动取 `PD /60`
`config-oci.json` 最简 7 字段：
```json
{
  "proxy_addr": "[::]:8080",
  "api_addr": "[::]:9191",
  "slaac_pool_size": 8,
  "selection_mode": "round-robin",
  "source_mode": "oci",
  "oci_prefix_length": 112,
  "oci_no_create": false
}
```
`oci_prefix_length=0` 逐IP池（32上限），`112/80` 单段自分配段内无限切，`oci_no_create=true` 只切不建段，留空 `prefix` 自动取 `enp0s6 /64`。控制台切换前缀后会写入 `oci_prefix_id`，重启时固定复用该前缀对象。切到第二个 VNIC 时还会写入 `oci_vnic_id`、`oci_source_iface`（如 `enp1s0`）和 `oci_wan_gateway`，三者都由实例元数据自动解析，重启后按 VNIC 重新确认接口名。

### VNIC 与 /64 切换（绕过 /64 封锁）
同一 VNIC/子网只能有一个 /64，因此换 /64 必须新建第二个子网并附加第二个 VNIC（实例通常最多 2 个 VNIC）。控制台的 VNIC 管理和 IPv6 前缀编辑是分开的：

1. 在「OCI 网卡（VNIC）」点「新建 VNIC」：在同一 VCN 的 Oracle `/56` 里挑一个未使用的 `/64`，从 VCN IPv4 段挑一个未使用的 `/24`，创建子网并附加新的 VNIC，**不会切换、也不会创建前缀**；
2. 在 VNIC 列表点「切换」：有前缀就复用，没有就按当前前缀长度新建，然后写入 `oci_prefix_id` / `oci_vnic_id` / `oci_source_iface` / `oci_wan_gateway` / `prefix`，构建新池并热加载；
3. 切换成功后，在下方「IPv6 前缀（当前 VNIC）」里编辑该 VNIC 的前缀；旧池的 `/128` 会从旧接口回收。新子网/VNIC 创建失败会自动回滚。

非当前、非主的 VNIC 可以直接点「删除」：控制台会先分离 VNIC，再删除它的子网（失败时会保留并给出警告）。主 VNIC（默认路由所在网卡）和当前正在使用的 VNIC 不允许删除。实例已有 2 个 VNIC 时需先删除旧的**非主** VNIC，才能再新建。

### 主机自身出口
新建/切换 VNIC 时，新网卡会通过 RA 安装一条 IPv6 默认路由；Linux 默认又优先 IPv6，所以主机自己的出口可能从原来的 `enp0s6` IPv4 变成 IPv6。这个行为与代理池无关，可在「配置 → 主机自身出口」里单独控制：

- **保持系统默认**：不修改主机路由，适合自己已经配好策略路由的环境
- **优先 IPv4**：写入 `/etc/gai.conf` 的受管块，主机程序优先选择 IPv4 出口
- **优先 IPv6（指定 VNIC）**：给主机默认路由加 metric 49，并指定走哪张 VNIC 的 `/64`
  - 可在「主机 IPv6 源地址」里固定具体源 IP；留空则自动选择（优先动态/SLAAC 地址，其次该网卡上的 `/128`）
  - 填写的地址若不在网卡上但在该 VNIC 的 `/64` 内，应用时会自动以 `/128` 加到网卡；其它网段的地址会被拒绝
  - 固定的源地址不会被「清理」删除，批量删池内地址时也会跳过（需先切换主机出口策略）
- **跟随代理当前 VNIC**：代理切换 VNIC 时，主机 IPv6 默认路由也跟着切换。`selection_mode=manual`（手动/固定）时会同时跟随被固定的那个 IPv6，系统出栈 IP 与代理出口保持一致；控制台「切换 IP / 固定」后会立即重新应用

这些设置只影响主机自己发起的连接，不会改变代理池的源地址。应用 IPv6 模式前会先为池内每个地址补上源地址策略路由，避免主机默认路由抢走代理流量。当前使用的 VNIC 和「主机出口」指定的 VNIC 不允许删除。

## 运行
```bash
./ipv6-proxy-linux-arm64 config-oci.json
# 或
./ipv6-proxy-linux-arm64 config.json
curl -x http://[::1]:8080 https://api64.ipify.org          # 轮询
curl -x http://[::1]:8080 -H "X-Source-IPv6: <ip>" https://api64.ipify.org  # 定向
curl -x socks5://<ip>:@\[::1\]:8080 https://api64.ipify.org
```

## API 与 Web 控制台
启动后浏览器打开 `http://<服务器>:9191/` 即是控制台（单文件内嵌，无需额外部署）：

- **概览**：地址总数 / 可用 / 不可用、当前出口 IP、代理地址一键复制、切换 IP、立即健康检查、批量生成并测试。新增「切换并检测出口 IP」与「检测当前出口」：通过本机代理实际请求 `https://api64.ipify.org`，返回真实出口并校验是否与当前地址一致
- **地址池**：每个地址的 alive/dead、路由/绑定/TCP/TLS/HTTPS 各阶段结果、公网回显、手动添加/删除/重测/固定
- **域名映射**：在线维护 `hosts`（域名 → 固定 IPv6 或别名域名），保存即写入配置文件
- **配置**：表单编辑全部 config 字段并保存。除 `proxy_addr` / `api_addr` 监听地址需要重启进程外，其余字段都会热加载：`selection_mode`、`failure_threshold`、`dns_server`、`test_target`、`api_token`、`hosts` 原地生效；`prefix`、`source_mode`、`subnet_count`、`slaac_pool_size`、`dummy_iface`、超时/重试、OCI 参数会先构建新地址池，成功后原子切换并回收旧池地址（保留共用地址和虚拟网卡）。保存响应里的 `applied` / `restart_required` 会列出实际结果
- **OCI**（仅 `source_mode=oci` 显示）：独立的「OCI」标签页，把 OCI 接入参数、VNIC 管理和 IPv6 前缀管理集中在这里，不再混在「配置」里。`source_mode` 切到非 `oci` 时该标签页自动隐藏，也不会再请求 OCI 接口
- **OCI VNIC / IPv6**（`source_mode=oci`，见「OCI」标签页）：「OCI 网卡（VNIC）」只负责新建、切换、删除 VNIC；切换成功后，才在「IPv6 前缀（当前 VNIC）」里管理该 VNIC 的前缀。可切换到任意已有前缀（或其它长度），也可让 OCI 在当前 `/64` 内新建一个前缀再切换。新建 VNIC 不会自动切换，也不会创建前缀。切换会重建地址池并热加载；旧前缀对象默认保留，勾选「切换成功后删除旧前缀对象」并二次确认后才会在切换成功后删除。`oci_prefix_id`、`oci_vnic_id`、`oci_source_iface`、`oci_wan_gateway` 会写入配置，重启后固定使用该段
- **主机自身出口**：「配置 → 主机自身出口」卡片可独立选择保持系统默认、优先 IPv4、指定 VNIC 的 IPv6 或跟随代理当前 VNIC。只影响主机自己发起的连接，不改变代理池；选择 IPv6 模式时会先把池内地址固定到各自的策略路由表，避免互相抢占
- **清理**：查看并删除残留的 dummy 虚拟网卡、残留 `/128`、策略路由规则/路由表。`source_mode=oci` 时会对比 OCI 控制台的 IPv6 对象，只清理**未入池、非动态、非前缀段**的本地 `/128`；`/112` 等前缀段和系统 SLAAC 地址始终保留。批量删除池内地址时可指定「保留数量」，并同步写入 `slaac_pool_size`，重启后不会恢复成原来的数量。虚拟网卡正在承载地址池时，须同时勾选「清空池内地址」才会删除，且删除后需重启进程恢复代理。前缀段请使用上面的「OCI 前缀切换」流程删除旧段
- **日志**：内存日志实时查看（支持自动刷新 / 行数切换）

JSON API（`[::]:9191`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 概览 + 运行配置 |
| GET | `/api/ips` | 池详情 |
| GET/POST | `/api/config` | 读取 / 保存配置 |
| GET/POST/DELETE | `/api/hosts` | 域名映射增删查 |
| POST/DELETE | `/api/addresses?ip=` | 手动加 / 删地址 |
| POST | `/api/addresses/test` | 重测单个地址 `{"ip":"..."}` |
| POST | `/api/healthcheck` | 触发全量健康检查 |
| GET/POST | `/api/host-egress` | 读取 / 应用主机自身出口策略。`{"mode":"system"}`、`{"mode":"ipv4"}`、`{"mode":"ipv6","vnic_id":"ocid1.vnic...","ip":"2603:..."}`、`{"mode":"proxy"}`；`mode=proxy` 会跟随代理固定 IP，`ip` 仅 `ipv6` 模式下可选，留空自动；只影响主机路由，不重建代理池 |
| GET/POST | `/api/egress-check` | 通过本机代理请求 `api64.ipify.org`，返回真实出口 IP；`?ip=` 指定并校验源地址 |
| GET | `/api/generate?count=N` | 生成 N 个随机地址并测试 |
| GET/POST | `/api/select?ip=..&next&mode=..` | 手动选择 |
| GET/POST | `/api/cleanup` | 预览 / 执行清理。批量删池内地址 `{"addresses":true,"keep":1}`（保留 1 个并同步 `slaac_pool_size`）；OCI 残留 `{"stale":true}`；删 OCI `/128` 对象 `{"delete_oci":["ocid..."]}`；路由 `{"routes":true}`；虚拟网卡 `{"dummy":true}` |
| GET/POST | `/api/oci/prefix` | 列出 / 管理 OCI VNIC 与前缀。`{"action":"new_vnic"}` 新建子网 + VNIC（不切换、不建前缀）；`{"action":"delete_vnic","vnic_id":"ocid1.vnic..."}` 分离并删除非当前、非主 VNIC；`{"action":"switch_vnic","vnic_id":"ocid1.vnic...","prefix_length":112,"delete_old":false}` 切到指定 VNIC（优先复用已有前缀，没有则新建）；`{"action":"use","id":"ocid1.ipv6...","vnic_id":"ocid1.vnic...","delete_old":false}` 切到已有段；`{"action":"rotate","prefix_length":112,"vnic_id":"...","delete_old":false}` 在指定 VNIC 的 /64 内新建并切换；`{"action":"new64","prefix_length":112,"delete_old":false}` 兼容旧接口：新建子网 + VNIC + 前缀并切换。仅在 `source_mode=oci` 可用；`delete_old=true` 只删除切换前的活动前缀对象 |
| GET | `/api/logs?lines=200` | 最近日志 |
| DELETE | `/api/logs` | 清空内存日志缓冲（不影响磁盘日志 / journald） |

### 保护 API
控制台可改配置和删地址，**不要裸奔在公网**。在配置里加 `api_token` 后所有 `/api/*` 都要带凭证：

```json
{ "api_token": "换成一个足够长的随机串" }
```

支持 `X-API-Token: <token>`、`Authorization: Bearer <token>` 或 `?token=<token>`。控制台会提示输入并记住在浏览器本地。Token 也可在「配置 → 安全」里在线设置/修改。


## OCI 要点
一张网卡最多 32 个 IPv6 对象；`/112` 一段 6 万 IP 已够用，池内 `/128` 由本机自分配，不会再额外创建 OCI 对象。

### OCI VNIC 与 IPv6 前缀
OCI 不支持原地修改前缀，切换 = 让地址池改用另一个前缀对象。控制台把两步分开：

1. 「OCI 网卡（VNIC）」列出已附加网卡，并标出接口、子网 `/64`、前缀数量和当前 VNIC。
2. 点「新建 VNIC」创建新子网 + VNIC（不切换、不建前缀）；点「删除」分离并删除非当前、非主的 VNIC 及其子网。
3. 点「切换」切到目标 VNIC：有前缀就复用，没有就按长度新建，然后重建地址池并热加载。
4. 切换成功后，「IPv6 前缀（当前 VNIC）」只显示当前 VNIC 的前缀。选择已有前缀点「切换到所选前缀」，或填写长度（80-128，4 的倍数）点「同 VNIC 新建前缀并切换」。
5. 后端先构建新地址池、写入 `oci_prefix_id` / `oci_vnic_id` / `oci_source_iface` / `oci_wan_gateway`，成功后再原子替换运行中的池；旧 `/128` 地址由旧池从旧接口回收。
6. 旧前缀对象默认保留。只有勾选「切换成功后删除旧前缀对象」并二次确认，才会在切换成功后删除**切换前的活动前缀对象**；如果旧前缀内还有其它 OCI IPv6 对象，删除会被拒绝并保留旧段。不会碰其它前缀或系统动态地址。
7. 切换失败会回滚新建的前缀、VNIC 和子网，旧池继续服务。

切换完成后 `config` 中会多出类似 `"oci_prefix_id": "ocid1.ipv6..."`、`"oci_vnic_id": "ocid1.vnic..."`、`"oci_source_iface": "enp1s0"`、`"oci_wan_gateway": "fe80::..."` 的字段，重启后仍固定使用该段。

**注意**：第二个子网的 `/64` 必须来自同一 VCN 的 Oracle `/56`。如果网站封锁整个 `/56`，需要新建 VCN（新的 Oracle `/56`），本项目不会自动跨 VCN 迁移。OCI 不允许同一子网出现第二个同源 `/64`。

### OCI 模式如何清理
- **池内地址（前缀自分配 `/112` 等）**：OCI 上只有一条前缀对象，池里的 IP 是本机 `ip addr add` 的 `/128`。控制台「清理 → 批量删除池内地址」按「保留数量」清理即可；这些 IP 不是独立 OCI 对象，删除后把 `slaac_pool_size` 设为保留数，重启不会恢复成 8 个。
- **OCI `/128` 对象（`oci_prefix_length=0`）**：每个 IP 都是 OCI 对象。先在地址池删除本地地址，再在「清理 → OCI IPv6 对象」勾选删除对应对象；只删本地地址的话，重启后 `ReconcileOci` 会从 OCI 重新加回来。
- **前缀段**：`/112`、`/80` 等前缀对象不会出现在清理的可删列表里。需要删除旧段时，用「OCI 前缀切换」切到新段并勾选删除旧段，或到 OCI 控制台手动删除。
- **系统 SLAAC 地址**：带 `dynamic noprefixroute` 的地址属于实例/运营商管理，永远会被跳过。
- **旧子网 / 旧 VNIC**：在「OCI 网卡（VNIC）」里对非当前、非主 VNIC 点「删除」，控制台会先分离 VNIC 再删除子网；删除失败时会保留并提示手动处理。主 VNIC 和当前正在使用的 VNIC 不会被删除。
