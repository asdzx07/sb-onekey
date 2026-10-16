#!/usr/bin/env python3
"""pref-sub 后端：静态服务 + sb-onekey 节点 API + 订阅生成"""
import base64
import json
import os
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

SB_NODES = "/etc/sing-box/nodes"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

# ---------- 订阅生成逻辑 ----------

def load_saved_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

import time
import urllib.request

REMOTE_CACHE = {}  # url -> (timestamp, text)
CACHE_TTL = 600    # 远程源缓存 10 分钟

def fetch_remote_text(url):
    now = time.time()
    if url in REMOTE_CACHE:
        ts, text = REMOTE_CACHE[url]
        if now - ts < CACHE_TTL and text:
            return text
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            content = resp.read()
            try:
                text = content.decode("utf-8")
            except Exception:
                text = content.decode("latin1", errors="ignore")
            
            # 自动检测 Base64 编码并解码
            clean_text = text.strip()
            if not any(proto in clean_text for proto in ["vless://", "vmess://", "http://", "https://", "#"]) and len(clean_text) > 30:
                try:
                    decoded = base64.b64decode(clean_text).decode("utf-8", errors="ignore")
                    if any(c in decoded for c in ["vless://", "vmess://", ":", "\n"]):
                        text = decoded
                except Exception:
                    pass
            REMOTE_CACHE[url] = (now, text)
            return text
    except Exception as e:
        if url in REMOTE_CACHE:
            return REMOTE_CACHE[url][1]
        return ""

def parse_single_line(line, default_port="443"):
    t = line.strip()
    if not t or t.startswith("#") or t.startswith("//"):
        return None

    # 1. 匹配标准协议链接 (如 vless://, trojan://, ss://) 并提取目标 IP、端口和备注
    for proto in ("vless://", "trojan://", "ss://"):
        if t.startswith(proto):
            label = ""
            url_part = t
            if "#" in t:
                url_part, raw_label = t.split("#", 1)
                label = urllib.parse.unquote(raw_label.strip())
            body = url_part.split("://", 1)[1]
            if "@" in body:
                body = body.split("@", 1)[1]
            host_part = body.split("?", 1)[0].split("/", 1)[0]
            ip, port = host_part, default_port
            if ":" in host_part and not host_part.startswith("["):
                parts = host_part.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    ip, port = parts[0], parts[1]
            ip = ip.strip("[]")
            if not label:
                label = ip
            return {"ip": ip, "port": port, "label": label}

    # 2. 匹配常见格式：IP:端口#备注 或 IP#备注 或 纯IP
    addr, label = t, ""
    if "#" in t:
        addr, label = t.split("#", 1)
        addr, label = addr.strip(), label.strip()
    ip, port = addr.strip(), default_port
    if ":" in addr and not addr.startswith("["):
        parts = addr.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            ip, port = parts[0], parts[1]
    ip = ip.strip("[]")
    if not label:
        label = ip
    return {"ip": ip, "port": port, "label": label}

def parse_ips(ip_text, default_port="443"):
    result = []
    for raw_line in (ip_text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # 挂载的远程 txt / 订阅链接 (http:// 或 https://)
        if line.startswith("http://") or line.startswith("https://"):
            remote_text = fetch_remote_text(line)
            for sub_line in remote_text.splitlines():
                item = parse_single_line(sub_line, default_port)
                if item and item.get("ip"):
                    ip_clean = item["ip"].strip()
                    if not ip_clean.startswith("http://") and not ip_clean.startswith("https://") and "/" not in ip_clean:
                        result.append(item)
            continue

        item = parse_single_line(line, default_port)
        if item and item.get("ip"):
            ip_clean = item["ip"].strip()
            if not ip_clean.startswith("http://") and not ip_clean.startswith("https://") and "/" not in ip_clean:
                result.append(item)
    return result

def dedup_labels(items):
    """去重节点名：重复的加 -2、-3 后缀"""
    seen = {}
    out = []
    for it in items:
        label = it["label"]
        if label in seen:
            seen[label] += 1
            label = f"{label}-{seen[label]}"
        else:
            seen[label] = 1
        out.append({**it, "label": label})
    return out

def clean_ws_path(path):
    p = (path or "").strip()
    if not p:
        return "/"
    if not p.startswith("/"):
        p = "/" + p
    return p

def build_vless_links(cfg):
    ips = dedup_labels(parse_ips(cfg.get("ipList", ""), cfg.get("port", "443")))
    links = []
    ws_path = clean_ws_path(cfg.get("path"))
    for it in ips:
        q = urllib.parse.urlencode({
            "security": "tls", "sni": cfg["host"], "type": "ws",
            "path": ws_path, "host": cfg["host"],
            "fp": "chrome", "encryption": "none",
        }, safe="/")
        links.append(f"vless://{cfg['uuid']}@{it['ip']}:{it['port']}?{q}#{urllib.parse.quote(it['label'])}")
    return links, ips

def gen_base64(cfg):
    links, _ = build_vless_links(cfg)
    return base64.b64encode("\n".join(links).encode()).decode()

def gen_clash(cfg):
    links, ips = build_vless_links(cfg)
    ips = dedup_labels(ips)
    node_names = [it["label"] for it in ips]
    sub_title = cfg.get("subName", "优选")

    out = [
        "port: 7890",
        "socks-port: 7891",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "unified-delay: true",
        "tcp-concurrent: true",
        "dns:",
        "  enable: true",
        "  ipv6: false",
        "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16",
        "  default-nameserver:",
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "  nameserver:",
        "    - https://223.5.5.5/dns-query",
        "    - https://119.29.29.29/dns-query",
        "  fallback:",
        "    - https://1.1.1.1/dns-query",
        "    - https://8.8.8.8/dns-query",
        "",
        "proxies:",
    ]
    ws_path = clean_ws_path(cfg.get("path"))
    for it in ips:
        out.append(f'  - name: "{it["label"]}"')
        out.append("    type: vless")
        out.append(f"    server: {it['ip']}")
        out.append(f"    port: {it['port']}")
        out.append(f"    uuid: {cfg['uuid']}")
        out.append("    udp: true")
        out.append("    tls: true")
        out.append(f"    servername: {cfg['host']}")
        out.append("    network: ws")
        out.append("    ws-opts:")
        out.append(f"      path: {ws_path}")
        out.append("      headers:")
        out.append(f"        Host: {cfg['host']}")

    # 策略组设计 (参考 sublink 体系)
    out.append("")
    out.append("proxy-groups:")
    # 1. 🚀 节点选择 (主选)
    out.append("  - name: \"🚀 节点选择\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append(f'      - "♻️ 自动选择"')
    out.append(f'      - "🎯 全局直连"')
    for pn in node_names:
        out.append(f'      - "{pn}"')

    # 2. ♻️ 自动选择 (url-test)
    out.append("  - name: \"♻️ 自动选择\"")
    out.append("    type: url-test")
    out.append("    url: https://www.gstatic.com/generate_204")
    out.append("    interval: 300")
    out.append("    tolerance: 50")
    out.append("    proxies:")
    for pn in node_names:
        out.append(f'      - "{pn}"')

    # 3. 🤖 AI 服务
    out.append("  - name: \"🤖 AI 服务\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - \"🚀 节点选择\"")
    out.append("      - \"♻️ 自动选择\"")
    out.append("      - \"🎯 全局直连\"")
    for pn in node_names:
        out.append(f'      - "{pn}"')

    # 4. 📹 YouTube
    out.append("  - name: \"📹 YouTube\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - \"🚀 节点选择\"")
    out.append("      - \"♻️ 自动选择\"")
    for pn in node_names:
        out.append(f'      - "{pn}"')

    # 5. 📲 Telegram
    out.append("  - name: \"📲 Telegram\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - \"🚀 节点选择\"")
    out.append("      - \"♻️ 自动选择\"")
    for pn in node_names:
        out.append(f'      - "{pn}"')

    # 6. 🐱 GitHub
    out.append("  - name: \"🐱 GitHub\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - \"🚀 节点选择\"")
    out.append("      - \"🎯 全局直连\"")
    out.append("      - \"♻️ 自动选择\"")
    for pn in node_names:
        out.append(f'      - "{pn}"')

    # 7. 🐟 Bilibili
    out.append("  - name: \"🐟 Bilibili\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - \"🎯 全局直连\"")
    out.append("      - \"🚀 节点选择\"")

    # 8. 🛑 广告拦截
    out.append("  - name: \"🛑 广告拦截\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - \"REJECT\"")
    out.append("      - \"🎯 全局直连\"")

    # 9. 🎯 全局直连
    out.append("  - name: \"🎯 全局直连\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - \"DIRECT\"")

    # 10. 🐟 漏网之鱼
    out.append("  - name: \"🐟 漏网之鱼\"")
    out.append("    type: select")
    out.append("    proxies:")
    out.append("      - \"🚀 节点选择\"")
    out.append("      - \"🎯 全局直连\"")
    out.append("      - \"♻️ 自动选择\"")

    # 规则集定义 (MetaCubeX .mrs 二进制规则)
    base_site = "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/"
    base_ip = "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geoip/"

    out.append("")
    out.append("rule-providers:")
    for rule_tag, file_name, btype in [
        ("category-ads-all", "category-ads-all.mrs", "domain"),
        ("category-ai", "category-ai-!cn.mrs", "domain"),
        ("youtube", "youtube.mrs", "domain"),
        ("google", "google.mrs", "domain"),
        ("telegram", "telegram.mrs", "domain"),
        ("github", "github.mrs", "domain"),
        ("bilibili", "bilibili.mrs", "domain"),
        ("cn-site", "geolocation-cn.mrs", "domain"),
    ]:
        out.append(f"  {rule_tag}:")
        out.append("    type: http")
        out.append(f"    behavior: {btype}")
        out.append("    format: mrs")
        out.append(f"    url: \"{base_site}{file_name}\"")
        out.append(f"    path: ./rules/{rule_tag}.mrs")
        out.append("    interval: 86400")

    for rule_tag, file_name in [
        ("cn-ip", "cn.mrs"),
        ("private-ip", "private.mrs"),
    ]:
        out.append(f"  {rule_tag}:")
        out.append("    type: http")
        out.append("    behavior: ipcidr")
        out.append("    format: mrs")
        out.append(f"    url: \"{base_ip}{file_name}\"")
        out.append(f"    path: ./rules/{rule_tag}.mrs")
        out.append("    interval: 86400")

    out.append("")
    out.append("rules:")
    out.append("  - RULE-SET,category-ads-all,🛑 广告拦截")
    out.append("  - RULE-SET,category-ai,🤖 AI 服务")
    out.append("  - RULE-SET,youtube,📹 YouTube")
    out.append("  - RULE-SET,google,🚀 节点选择")
    out.append("  - RULE-SET,telegram,📲 Telegram")
    out.append("  - RULE-SET,github,🐱 GitHub")
    out.append("  - RULE-SET,bilibili,🐟 Bilibili")
    out.append("  - RULE-SET,cn-site,🎯 全局直连")
    out.append("  - RULE-SET,private-ip,🎯 全局直连,no-resolve")
    out.append("  - RULE-SET,cn-ip,🎯 全局直连")
    out.append("  - GEOIP,CN,🎯 全局直连")
    out.append("  - MATCH,🐟 漏网之鱼")
    return "\n".join(out)

def gen_singbox(cfg):
    links, ips = build_vless_links(cfg)
    ips = dedup_labels(ips)
    node_tags = [it["label"] for it in ips]

    ws_path = clean_ws_path(cfg.get("path"))

    # 1. 策略组置顶 (确保客户端 GUI 首屏识别主选择器与分组)
    group_outbounds = [
        {
            "type": "selector", "tag": "🚀 节点选择",
            "outbounds": ["♻️ 自动选择", "🎯 全局直连"] + node_tags,
            "default": "♻️ 自动选择" if node_tags else "🎯 全局直连"
        },
        {
            "type": "urltest", "tag": "♻️ 自动选择",
            "outbounds": node_tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "300s",
            "tolerance": 50
        },
        {
            "type": "selector", "tag": "🤖 AI 服务",
            "outbounds": ["🚀 节点选择", "♻️ 自动选择", "🎯 全局直连"] + node_tags,
            "default": "🚀 节点选择"
        },
        {
            "type": "selector", "tag": "📹 YouTube",
            "outbounds": ["🚀 节点选择", "♻️ 自动选择"] + node_tags,
            "default": "🚀 节点选择"
        },
        {
            "type": "selector", "tag": "📲 Telegram",
            "outbounds": ["🚀 节点选择", "♻️ 自动选择"] + node_tags,
            "default": "🚀 节点选择"
        },
        {
            "type": "selector", "tag": "🐱 GitHub",
            "outbounds": ["🚀 节点选择", "🎯 全局直连", "♻️ 自动选择"] + node_tags,
            "default": "🚀 节点选择"
        },
        {
            "type": "selector", "tag": "🐟 Bilibili",
            "outbounds": ["🎯 全局直连", "🚀 节点选择"],
            "default": "🎯 全局直连"
        },
    ]

    # 2. 单节点列表
    node_outbounds = []
    for it in ips:
        node_outbounds.append({
            "type": "vless", "tag": it["label"],
            "server": it["ip"], "server_port": int(it["port"]),
            "uuid": cfg["uuid"],
            "tls": {"enabled": True, "server_name": cfg["host"],
                    "utls": {"enabled": True, "fingerprint": "chrome"}},
            "transport": {"type": "ws", "path": ws_path,
                          "headers": {"Host": cfg["host"]}},
        })

    # 3. 基础出站 (移除已在 1.11 弃用的 block 与 dns 虚拟出站)
    # DIRECT 专供 DNS detour 用（1.15 不认空 direct 出站做 detour）
    infra_outbounds = [
        {"type": "direct", "tag": "DIRECT"},
        {"type": "direct", "tag": "🎯 全局直连"}
    ]

    outbounds = group_outbounds + node_outbounds + infra_outbounds

    base_site = "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/"
    base_ip = "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geoip/"

    rule_sets = [
        {"tag": "geosite-ads", "type": "remote", "format": "binary", "url": f"{base_site}category-ads-all.srs", "http_client": "http-proxy"},
        {"tag": "geosite-ai", "type": "remote", "format": "binary", "url": f"{base_site}category-ai-!cn.srs", "http_client": "http-proxy"},
        {"tag": "geosite-youtube", "type": "remote", "format": "binary", "url": f"{base_site}youtube.srs", "http_client": "http-proxy"},
        {"tag": "geosite-telegram", "type": "remote", "format": "binary", "url": f"{base_site}telegram.srs", "http_client": "http-proxy"},
        {"tag": "geosite-github", "type": "remote", "format": "binary", "url": f"{base_site}github.srs", "http_client": "http-proxy"},
        {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": f"{base_site}geolocation-cn.srs", "http_client": "http-direct"},
        {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": f"{base_ip}cn.srs", "http_client": "http-direct"},
        {"tag": "geoip-private", "type": "remote", "format": "binary", "url": f"{base_ip}private.srs", "http_client": "http-direct"},
    ]

    # 对齐 sublink：嗅探与 DNS 劫持均通过规则动作（Action）处理，不再依赖 inbound 旧字段
    rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"rule_set": "geosite-ads", "action": "reject"},
        {"rule_set": "geosite-ai", "outbound": "🤖 AI 服务"},
        {"rule_set": "geosite-youtube", "outbound": "📹 YouTube"},
        {"rule_set": "geosite-telegram", "outbound": "📲 Telegram"},
        {"rule_set": "geosite-github", "outbound": "🐱 GitHub"},
        {"rule_set": "geosite-cn", "outbound": "🎯 全局直连"},
        {"rule_set": ["geoip-private", "geoip-cn"], "outbound": "🎯 全局直连"},
    ]

    sb_config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "dns_proxy", "type": "https",
                    "server": "1.1.1.1", "path": "/dns-query",
                    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                    "detour": "🚀 节点选择"
                },
                {
                    "tag": "dns_direct", "type": "https",
                    "server": "223.5.5.5", "path": "/dns-query",
                    "tls": {"enabled": True, "server_name": "dns.alidns.com"}
                },
                {
                    "tag": "dns_fakeip", "type": "fakeip",
                    "inet4_range": "198.18.0.0/15"
                }
            ],
            "rules": [
                {"rule_set": "geosite-ads", "action": "reject"},
                {"rule_set": "geosite-cn", "server": "dns_direct"},
                {"query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"},
                {"query_type": ["A"], "server": "dns_fakeip"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080},
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "auto_route": True, "strict_route": True}
        ],
        "outbounds": outbounds,
        "route": {
            "default_domain_resolver": "dns_direct",
            "default_http_client": "http-proxy",
            "rule_set": rule_sets,
            "rules": rules,
            "final": "🚀 节点选择",
            "auto_detect_interface": True
        },
        "http_clients": [
            {"tag": "http-proxy", "detour": "🚀 节点选择"},
            {"tag": "http-direct"}
        ],
        "experimental": {
            "cache_file": {
                "enabled": True,
                "store_fakeip": True
            },
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "default_mode": "rule"
            }
        }
    }
    return json.dumps(sb_config, ensure_ascii=False, indent=2)

# ---------- HTTP 服务 ----------

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/nodes":
            self.send_json(self.get_local_nodes())
        elif parsed.path == "/api/config":
            self.send_json(load_saved_config())
        elif parsed.path.startswith("/sub/"):
            self.serve_sub(parsed.path[5:])
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/save":
            length = int(self.headers.get("Content-Length", 0))
            cfg = json.loads(self.rfile.read(length) or b"{}")
            save_config(cfg)
            ips = parse_ips(cfg.get("ipList", ""), cfg.get("port", "443"))
            self.send_json({"ok": True, "count": len(ips)})
        elif parsed.path == "/api/expand_ips":
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
            ips = parse_ips(data.get("ipList", ""), data.get("port", "443"))
            formatted = "\n".join([f"{item['ip']}:{item['port']}#{item['label']}" for item in ips])
            self.send_json({"ok": True, "count": len(ips), "text": formatted})
        else:
            self.send_response(404)
            self.end_headers()

    def get_local_nodes(self):
        nodes = []
        if os.path.isdir(SB_NODES):
            for fn in sorted(os.listdir(SB_NODES)):
                if not fn.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(SB_NODES, fn)) as f:
                        meta = json.load(f)
                    if meta.get("proto") not in ("vless-ws-tls", "vless-ws"):
                        continue
                    nodes.append({
                        "tag": meta.get("tag"), "name": meta.get("name"),
                        "proto": meta.get("proto"), "uuid": meta.get("uuid"),
                        "port": meta.get("port"), "path": meta.get("path"),
                        "host": meta.get("sni_v4") or meta.get("domain"),
                        "created": meta.get("created"),
                    })
                except Exception:
                    continue
        nodes.sort(key=lambda x: x.get("created") or "")
        return {"nodes": nodes, "sb_installed": os.path.isdir(SB_NODES)}

    def serve_sub(self, kind):
        cfg = load_saved_config()
        if not cfg.get("uuid") or not cfg.get("host"):
            self.send_text("请先在 WebUI 中保存节点配置和优选 IP", 400)
            return
        if kind == "vless":
            body, ctype = "\n".join(build_vless_links(cfg)[0]), "text/plain; charset=utf-8"
        elif kind == "base64":
            body, ctype = gen_base64(cfg), "text/plain; charset=utf-8"
        elif kind == "clash":
            body, ctype = gen_clash(cfg), "text/yaml; charset=utf-8"
        elif kind == "singbox":
            body, ctype = gen_singbox(cfg), "application/json; charset=utf-8"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_text(body, 200, ctype)

    def send_json(self, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, code=200, ctype="text/plain; charset=utf-8"):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "13530"))
    print(f"pref-sub on port {port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
