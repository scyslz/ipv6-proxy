#!/usr/bin/env python3
import subprocess, json, sys, os
from pathlib import Path

def run(cmd): return subprocess.check_output(cmd, shell=True, text=True)

def list_oci():
    # 复用 oci-ipv6-manager.py 的 List 逻辑，简化直接调它
    out = run("python3 /home/ubuntu/ipv6-proxy/oci-ipv6-manager.py --list-oci 2>&1 | tail -n +2")
    data = json.loads(out)
    return data

def list_local():
    out = run("ip -6 addr show dev enp0s6 | grep '2603:c024:4517:a81e' | awk '{print $2}' | cut -d/ -f1")
    return [x.strip() for x in out.splitlines() if x.strip()]

if __name__ == "__main__":
    try:
        oci = list_oci()
    except Exception as e:
        print(f"OCI 列表失败 {e}，改用本地")
        oci = []
    # 优先用 OCI，若失败用本地
    ips = []
    if oci:
        for o in oci:
            ip = o["ipAddress"]
            # 若是 /112 前缀，展开示例取前 5 个自切演示
            if o.get("cidrPrefixLength"):
                # 7d21:0/112 -> 展示段内几个示例
                base = ip.rsplit(":",1)[0]  # 简化
                for suffix in ["1","ff","a","b","c"]:
                    # 仅演示，实际段内任意 suffix 均可 ip addr add
                    pass
                ips.append(f"{ip}/{o['cidrPrefixLength']} (段)")
                # 同时列出本机已在该段内自建的 8 个
                for lip in list_local():
                    if lip.startswith(ip.split("::")[0].split(":")[0]): # 粗略
                        pass
            else:
                ips.append(ip)
        # 追加本机段内自建的
        for lip in list_local():
            if lip not in ips:
                ips.append(lip+" (本地)")
    else:
        ips = list_local()

    # 去重
    uniq = []
    for x in ips:
        if x not in uniq:
            uniq.append(x)
    print("可选 IP 列表：")
    for i, ip in enumerate(uniq, 1):
        print(f"  {i}. {ip}")
    if not uniq:
        print("无可用 IP")
        sys.exit(0)
    try:
        n = input(f"输入序号切换 [1-{len(uniq)}] (回车退出): ").strip()
        if not n: sys.exit(0)
        idx = int(n)-1
        sel = uniq[idx].split()[0].split("/")[0]
    except Exception as e:
        print(f"输入无效 {e}"); sys.exit(1)
    print(f"切换默认出口到 {sel} ...")
    # 方式1：改默认路由 src（立即生效，需 metric 10 覆盖 RA 100）
    cmd = f"sudo ip -6 route replace default via fe80::200:17ff:feae:d75 dev enp0s6 src {sel} metric 10"
    print("$", cmd)
    os.system(cmd)
    # 方式2：如需持久，写 netplan（可选注释）
    # with open("/etc/netplan/99-ipv6.yaml","w") as f: f.write(f"network:\n  version: 2\n  ethernets:\n    enp0s6:\n      addresses: [{sel}/128]\n")
    # os.system("sudo netplan apply")
    print("当前出口：", run(f"curl -s --interface {sel} https://api64.ipify.org"))
    print("或 curl https://api64.ipify.org 验证默认")
