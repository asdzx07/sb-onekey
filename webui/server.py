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

def parse_ips(ip_text, default_port="443"):
    result = []
    for line in (ip_text or "").split("\n"):
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        addr, label = t, ""
        if "#" in t:
            addr, label = t.split("#", 1)
            addr, label = addr.strip(), label.strip()
        ip, port = addr.strip(), default_port
        # IPv6 简单处理
        if ":" in addr and not addr.startswith("["):
            parts = addr.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                ip, port = parts
        ip = ip.strip("[]")
        if not label:
            label = ip
        result.append({"ip": ip, "port": port, "label": label})
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

def build_vless_links(cfg):
    ips = dedup_labels(parse_ips(cfg.get("ipList", ""), cfg.get("port", "443")))
    links = []
    for it in ips:
        q = urllib.parse.urlencode({
            "security": "tls", "sni": cfg["host"], "type": "ws",
            "path": cfg.get("path") or "/", "host": cfg["host"],
            "fp": "chrome", "encryption": "none",
        })
        links.append(f"vless://{cfg['uuid']}@{it['ip']}:{it['port']}?{q}#{urllib.parse.quote(it['label'])}")
    return links, ips

def gen_base64(cfg):
    links, _ = build_vless_links(cfg)
    return base64.b64encode("\n".join(links).encode()).decode()

def gen_clash(cfg):
    links, ips = build_vless_links(cfg)
    ips = dedup_labels(ips)
    out = ["proxies:"]
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
        out.append(f"      path: {cfg.get('path') or '/'}")
        out.append("      headers:")
        out.append(f"        Host: {cfg['host']}")
    out.append("")
    out.append("proxy-groups:")
    out.append(f'  - name: "{cfg.get("subName", "优选")}"')
    out.append("    type: url-test")
    out.append("    proxies:")
    for it in ips:
        out.append(f'      - "{it["label"]}"')
    out.append("    url: https://www.gstatic.com/generate_204")
    out.append("    interval: 300")
    out.append("")
    out.append("rules:")
    out.append(f'  - MATCH,{cfg.get("subName", "优选")}')
    return "\n".join(out)

def gen_singbox(cfg):
    links, ips = build_vless_links(cfg)
    ips = dedup_labels(ips)
    outbounds = []
    for it in ips:
        outbounds.append({
            "type": "vless", "tag": it["label"],
            "server": it["ip"], "server_port": int(it["port"]),
            "uuid": cfg["uuid"],
            "tls": {"enabled": True, "server_name": cfg["host"],
                    "utls": {"enabled": True, "fingerprint": "chrome"}},
            "transport": {"type": "ws", "path": cfg.get("path") or "/",
                          "headers": {"Host": cfg["host"]}},
        })
    outbounds.append({"type": "direct", "tag": "direct"})
    return json.dumps({
        "log": {"level": "info"},
        "outbounds": outbounds,
        "route": {"rules": [], "final": outbounds[0]["tag"] if outbounds else "direct"},
    }, ensure_ascii=False, indent=2)

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
            self.send_json({"ok": True})
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
