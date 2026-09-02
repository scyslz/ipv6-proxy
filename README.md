# IPv6 出站代理

轻量 Go 代理，一行命令让多个 IPv6 轮流出站。家庭 `PD` 与 `OCI` 双场景。

## 文件
```
ipv6-proxy/
├── main.go            # 入口
├── internal/          # 拆分模块（config/pool/network/dns/proxy/api/oci）
├── config.json        # 家庭 pool
├── config-oci.json    # OCI（oci_prefix_length=112 单段 6万IP）
├── go.mod
└── README.md
```
调研见 `RESEARCH.md`（家庭）/`RESEARCH-OCI.md`（OCI 通俗版）。

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
`oci_prefix_length=0` 逐IP池（32上限），`112/80` 单段自分配段内无限切，`oci_no_create=true` 只切不建段，留空 `prefix` 自动取 `enp0s6 /64`。

## 运行
```bash
./ipv6-proxy-linux-arm64 config-oci.json
# 或
./ipv6-proxy-linux-arm64 config.json
curl -x http://[::1]:8080 https://api64.ipify.org          # 轮询
curl -x http://[::1]:8080 -H "X-Source-IPv6: <ip>" https://api64.ipify.org  # 定向
curl -x socks5://<ip>:@\[::1\]:8080 https://api64.ipify.org
```

## API
`[::]:9191/api/status` 概览，`/api/ips` 池详情，`/api/select?ip=..&next` 手切。

## OCI 要点
一张网卡 32 对象，`112` 一段 6万 IP 已够；`DELETE` 旧段再 `POST` 即换段，`RESEARCH-OCI.md` 有一键命令。
