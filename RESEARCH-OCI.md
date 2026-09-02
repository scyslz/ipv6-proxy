# OCI IPv6 简单调研

## 一句话
OCI 不能像家庭宽带那样随便造地址，每个 IPv6 都要先在网页或 API 上申请，申请后才能在机器上使用。

## 本机情况
- 网卡 `enp0s6`，前缀 `2603:c024:4517:a81e::/64`
- 已申请 3 个固定 IP：`709f`、`95de`、`1c47::`，1 个前缀段 `7d21:1a63:5b61:0/112`

## 能拿多少
- 一张网卡最多同时挂 32 个对象，机器最多 2 张网卡共 64 个
- 1 个对象可以是 1 个 IP（`/128`），也可以是一段（`/112` 有 6万个 IP，`/80` 有很多），所以 1 段就够日常切换

## 怎么申请
- 单 IP：调一下 API 就给一个新 IP
- 一段：申请 `/112` 这样的段，比如 `7d21:1a63:5b61:0/112`，段内 `7d21:1a63:5b61:1` 到 `ffff` 都能自己 `ip addr add` 直接用，不用每个都申请
- 删了再申请就能换新段，网卡不会断

## 代理怎么切
- 代理已支持 `source_mode=oci`，启动时自动读已申请的 IP 或段，生成 8 个本地地址轮流用
- 想只切 IP 不换段：`oci_no_create=true`，只用已有段
- 想换段：删掉旧段重启就会拿到新段

## 怎么试
```bash
python3 oci-ipv6-manager.py --list-oci   # 看已有
python3 oci-ipv6-manager.py --assign     # 申请一个
sudo ./ipv6-proxy-internal configs/config-oci-prefix.json
curl -x http://[::1]:8080 https://api64.ipify.org  # 每次换 IP
```
