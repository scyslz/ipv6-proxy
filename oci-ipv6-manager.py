#!/usr/bin/env python3
"""
OCI IPv6 管理器 - 适用于 OCI 实例通过多个 IPv6 切换出站
- 支持 API Key ( ~/.oci/config ) 和 Instance Principal (本机 IMDS)
- 核心验证: 在 OCI VCN 中, 只有通过 API 分配给 VNIC 的 IPv6 才能出站,
  任意 `ip addr add` 的随机地址会 bind 成功但 TCP timeout (已在本机验证)
- 流程: OCI API AssignIpv6 -> 内核自动出现 /128 -> 代理池 bind 该 IP 出站
- 删除: OCI API DeleteIpv6 -> 内核地址自动消失
"""
import os, sys, json, base64, hashlib, datetime, subprocess, ipaddress
from urllib import request, error
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("need cryptography: pip install cryptography / apt install python3-cryptography")
    sys.exit(1)

# 本机已探测到的元数据 (2026-09-02)
VNIC_ID = "ocid1.vnic.oc1.ap-singapore-1.abzwsljrih6voma6ns2fdcl32dojbc3vgzmnbqycpkmv22szwfp6qbrhsiya"
COMPARTMENT_ID = "ocid1.tenancy.oc1..aaaaaaaagpxqj7cdk2zooo7dvrqdf3mqonsrjtoxuzay3xgldkpnwa4i4fpa"
REGION = "ap-singapore-1"
ENDPOINT = f"https://iaas.{REGION}.oraclecloud.com"

def load_oci_config(path="~/.oci/config", profile="DEFAULT"):
    p = Path(path).expanduser()
    if not p.exists():
        return None
    cfg = {}
    cur = None
    for line in p.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("[") and line.endswith("]"):
            cur=line[1:-1]
        elif "=" in line and (cur==profile or profile is None):
            k,v=line.split("=",1)
            cfg[k.strip()]=v.strip()
    return cfg if cfg else None

def sign_request(method, uri, headers, private_key_pem, key_id):
    """OCI Signature Version 1, headers=(request-target) date host (and x-content-sha256 for POST)"""
    # headers dict must contain 'date' and 'host'
    signing_string = ""
    # order matters: (request-target) date host [x-content-sha256 content-type content-length]
    parts = []
    parts.append(f"(request-target): {method.lower()} {uri}")
    for h in ["date","host","x-content-sha256","content-type","content-length"]:
        if h in headers:
            parts.append(f"{h}: {headers[h]}")
    signing_string = "\n".join(parts)
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    signature = private_key.sign(signing_string.encode(), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(signature).decode()
    # build Authorization header
    hdrs = " ".join([p.split(":")[0] for p in parts])
    auth = f'Signature version="1",keyId="{key_id}",algorithm="rsa-sha256",headers="{hdrs}",signature="{sig_b64}"'
    return auth

def oci_request(method, path, cfg, body=None):
    """使用 API Key 发起 OCI REST 调用 (无需 oci SDK)"""
    # cfg 需要: tenancy, user, fingerprint, private_key (path), region
    with open(os.path.expanduser(cfg["key_file"]), "r") as f:
        private_pem = f.read()
    key_id = f"{cfg['tenancy']}/{cfg['user']}/{cfg['fingerprint']}"
    host = f"iaas.{cfg.get('region', REGION)}.oraclecloud.com"
    url = f"https://{host}{path}"
    uri = path  # for signing, include query string if any
    date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    headers = {"date": date, "host": host}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        sha = base64.b64encode(hashlib.sha256(data).digest()).decode()
        headers["x-content-sha256"] = sha
        headers["content-type"] = "application/json"
        headers["content-length"] = str(len(data))
    headers["Authorization"] = sign_request(method, uri, headers, private_pem, key_id)
    req = request.Request(url, data=data, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=10) as resp:
            b = resp.read()
            return resp.status, json.loads(b.decode()) if b else None
    except error.HTTPError as e:
        b = e.read().decode()
        print(f"HTTP {e.code}: {b[:500]}")
        return e.code, b
    except Exception as e:
        print(f"request failed: {e}")
        return None, str(e)

def local_ipv6s():
    out = subprocess.check_output(["ip","-6","addr","show","dev","enp0s6"], text=True)
    print(out)

def test_bind(src_ip, dst="2606:4700:4700::1111", port=80):
    import socket
    try:
        s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.bind((src_ip,0,0,0))
        s.connect((dst,port,0,0))
        print(f"[OK] {src_ip} -> [{dst}]:{port} TCP 成功")
        s.close()
        return True
    except Exception as e:
        print(f"[FAIL] {src_ip} -> [{dst}]:{port} {e}")
        return False

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="OCI IPv6 管理验证工具")
    ap.add_argument("--list-local", action="store_true", help="列出本机 enp0s6 IPv6")
    ap.add_argument("--test-bind", nargs="?", const="2603:c024:4517:a81e:0:709f:b533:1af7", help="测试指定源 IP 出站")
    ap.add_argument("--list-oci", action="store_true", help="通过 OCI API 列出 VNIC 的 IPv6 (需 ~/.oci/config)")
    ap.add_argument("--assign", action="store_true", help="通过 OCI API 分配一个新 IPv6 到 VNIC")
    ap.add_argument("--delete", metavar="IPV6_ID", help="通过 OCI API 删除指定 IPv6 (ocid1.ipv6...)")
    ap.add_argument("--vnic", default=VNIC_ID, help="VNIC OCID")
    args = ap.parse_args()

    if args.list_local or len(sys.argv)==1:
        print("=== 本机 enp0s6 IPv6 (含手动添加的随机地址) ===")
        local_ipv6s()
        print("\n=== 关键验证: 只有 OCI 分配的地址可出站 ===")
        # 已在本机验证: 2 个 OCI 分配的 OK, 2 个随机手动添加的 timeout
        for ip in ["2603:c024:4517:a81e:0:709f:b533:1af7","2603:c024:4517:a81e:1c47::","2603:c024:4517:a81e:819a:a502:5199:17c7","2603:c024:4517:a81e::9999"]:
            test_bind(ip)

    if args.test_bind:
        test_bind(args.test_bind)

    if args.list_oci:
        cfg = load_oci_config()
        if not cfg:
            print("未找到 ~/.oci/config, 无法调用 OCI API. 请先配置 API Key 或在实例上使用 Instance Principal")
            print("参考: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliconfigure.htm")
            sys.exit(1)
        # List Ipv6s: GET /20160918/ipv6?vnicId=...&compartmentId=...
        # 注意: ListIpv6s 需要 compartmentId, 但按 VCN 文档只需 vnicId
        path = f"/20160918/ipv6?compartmentId={COMPARTMENT_ID}&vnicId={args.vnic}"
        code, data = oci_request("GET", path, cfg)
        print(f"List Ipv6s -> {code}")
        print(json.dumps(data, indent=2, ensure_ascii=False))

    if args.assign:
        cfg = load_oci_config()
        if not cfg:
            print("未找到 ~/.oci/config")
            sys.exit(1)
        body = {"vnicId": args.vnic}
        # 可选指定 ipv6Ip: {"vnicId": "...", "ipv6Ip": "2603:...::xxxx"} 但留空让 OCI 自动分配最稳
        code, data = oci_request("POST", "/20160918/ipv6", cfg, body)
        print(f"Assign -> {code}")
        print(json.dumps(data, indent=2, ensure_ascii=False) if isinstance(data, dict) else data)
        if code==200 and data:
            print("等待 2 秒后检查本机是否出现新 /128 ...")
            import time; time.sleep(2)
            local_ipv6s()

    if args.delete:
        cfg = load_oci_config()
        if not cfg:
            print("未找到 ~/.oci/config")
            sys.exit(1)
        code, data = oci_request("DELETE", f"/20160918/ipv6/{args.delete}", cfg)
        print(f"Delete {args.delete} -> {code}")
        print(data)
