#!/bin/bash
# sing-box 一键脚本 v2 (server 端)
# 6 种主流协议 / 交互+一键双模式 / 证书自动检测 / 订阅三件套
# 用法: sudo bash sing-box.sh              (交互菜单)
#       sudo bash sing-box.sh --onekey     (零交互一键搭建 REALITY)
#       sudo bash sing-box.sh --add-reality [--port 443] [--domain www.microsoft.com]
#       sudo bash sing-box.sh --add-tuic | --add-hy2 | --add-anytls | --add-ws | --add-ws-tls
#       sudo bash sing-box.sh --show | --update | --self-update | --uninstall

SCRIPT_VER="2.0.1"
REPO="asdzx07/sb-onekey"   # 发布后如改名只改这一行

set -u
SB_DIR="/etc/sing-box"
SB_CONF="$SB_DIR/config.json"
SB_NODES="$SB_DIR/nodes"
SB_SUB="$SB_DIR/sub"
SB_CERTS="$SB_DIR/certs"
SB_MANUAL_CERTS="$SB_DIR/certs-manual.json"
SB_BIN="/usr/local/bin/sing-box"
SB_SERVICE="/etc/systemd/system/sing-box.service"
SB_SUB_SERVICE="/etc/systemd/system/sing-box-sub.service"

REALITY_DOMAINS=(
  "aws.amazon.com" "www.amd.com" "www.amazon.com" "dl.google.com"
  "www.nvidia.com" "www.microsoft.com" "www.intel.com" "www.samsung.com"
)

# ---------- 输出 ----------
_red()    { echo -e "\033[31m$*\033[0m"; }
_green()  { echo -e "\033[32m$*\033[0m"; }
_yellow() { echo -e "\033[33m$*\033[0m"; }
_cyan()   { echo -e "\033[36m$*\033[0m"; }
info() { echo -e "$(_cyan "[*]") $*"; }
ok()   { echo -e "$(_green "[✓]") $*"; }
warn() { echo -e "$(_yellow "[!]") $*"; }
err()  { echo -e "$(_red "[✗]") $*"; }

# 读取菜单选择，清洗不可见字符和首尾空格
read_choice() {
  local input
  read -rp "$1" input
  echo "$input" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# ---------- 基础 ----------
check_root() {
  if [ "$(id -u)" -ne 0 ]; then err "请用 root 运行"; exit 1; fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) err "不支持的架构: $(uname -m)"; exit 1 ;;
  esac
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "缺少命令: $1，请先安装"; exit 1; }
}

get_public_ip() {
  # $1: 非交互=1 时失败不提示直接返回非0
  local ip noninteractive="${1:-0}"
  ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null) \
    || ip=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null)
  if [ -z "$ip" ]; then
    if [ "$noninteractive" = "1" ]; then return 1; fi
    read -rp "无法自动获取公网 IPv4，请手动输入: " ip
  fi
  echo "$ip"
}

get_public_ip6() {
  local ip
  ip=$(curl -s --max-time 5 -6 https://api6.ipify.org 2>/dev/null) \
    || ip=$(curl -s --max-time 5 -6 https://ifconfig.me 2>/dev/null)
  echo "$ip"
}

# ---------- 端口 ----------
port_in_use() { ss -tuln 2>/dev/null | grep -q ":$1 "; }

ensure_port_free() {
  # 入口防崩溃：被占用直接报错退出，不动配置
  [ -n "${1:-}" ] || { err "端口为空"; return 1; }
  if port_in_use "$1"; then
    err "端口 $1 已被占用，换个端口再试"
    return 1
  fi
}

random_port() {
  local p tries=0
  while [ $tries -lt 20 ]; do
    p=$((RANDOM % 50001 + 10000))
    port_in_use "$p" || { echo "$p"; return 0; }
    tries=$((tries + 1))
  done
  err "随机端口 20 次都没挑到空闲的，手动指定吧"
  return 1
}

# ---------- 交互输入 ----------
ask_domain() {
  # $1: 默认值
  local dflt="${1:-bing.com}" input
  read -rp "域名 [回车=${dflt}]: " input
  echo "${input:-$dflt}"
}

ask_port() {
  # $1: 用途描述。回车=随机
  local input p
  while :; do
    read -rp "端口 [回车=随机]: " input
    if [ -z "$input" ]; then
      p=$(random_port) || continue
      info "随机端口: $p"
      echo "$p"; return 0
    fi
    if ! [[ "$input" =~ ^[0-9]+$ ]] || [ "$input" -lt 1 ] || [ "$input" -gt 65535 ]; then
      warn "端口不合法"; continue
    fi
    if port_in_use "$input"; then warn "端口 $input 已被占用"; continue; fi
    echo "$input"; return 0
  done
}

ask_uuid() {
  local input
  read -rp "UUID [回车=随机生成]: " input
  echo "${input:-$(cat /proc/sys/kernel/random/uuid)}"
}

ask_password() {
  local input
  read -rp "密码 [回车=随机生成]: " input
  echo "${input:-$(openssl rand -hex 12)}"
}

ask_addr_mode() {
  # 链接地址模式：1=v4 2=v6 3=都要
  local input
  read -rp "客户端链接地址 [1]IPv4 [2]IPv6 [3]都要 (回车=3): " input
  case "${input:-3}" in
    1) echo 1 ;; 2) echo 2 ;; *) echo 3 ;;
  esac
}

# ---------- 证书自动检测 ----------
declare -A CERT_MAP  # 域名 -> "cert|key"
declare -A CERT_SRC  # 域名 -> 来源说明

cert_valid_for() {
  local cert="$1" domain="$2"
  openssl x509 -checkend 0 -noout -in "$cert" 2>/dev/null || return 1
  if openssl x509 -noout -in "$cert" -ext subjectAltName 2>/dev/null | grep -q "DNS:${domain}"; then
    return 0
  fi
  openssl x509 -noout -in "$cert" -subject 2>/dev/null | grep -qE "CN *= *${domain}" && return 0
  return 1
}

cert_expiry() {
  openssl x509 -noout -in "$1" -enddate 2>/dev/null | cut -d= -f2
}

detect_certs() {
  CERT_MAP=(); CERT_SRC=()
  local d domain c k f base
  for d in /root/.acme.sh/*/ "$HOME"/.acme.sh/*/; do
    [ -d "$d" ] || continue
    domain=$(basename "$d"); [[ "$domain" == .* ]] && continue
    c="${d}fullchain.cer"; k="${d}${domain}.key"
    if [ -f "$c" ] && [ -f "$k" ] && cert_valid_for "$c" "$domain"; then
      CERT_MAP["$domain"]="$c|$k"; CERT_SRC["$domain"]="acme.sh 自动检测"
    fi
  done
  for d in /etc/letsencrypt/live/*/; do
    [ -d "$d" ] || continue
    domain=$(basename "$d")
    c="${d}fullchain.pem"; k="${d}privkey.pem"
    if [ -f "$c" ] && [ -f "$k" ] && cert_valid_for "$c" "$domain"; then
      CERT_MAP["$domain"]="$c|$k"; CERT_SRC["$domain"]="certbot 自动检测"
    fi
  done
  for f in "$SB_CERTS"/*.crt; do
    [ -f "$f" ] || continue
    base=$(basename "$f" .crt); k="$SB_CERTS/${base}.key"
    if [ -f "$k" ] && cert_valid_for "$f" "$base"; then
      CERT_MAP["$base"]="$f|$k"; CERT_SRC["$base"]="脚本自签"
    fi
  done
  # 手动添加的优先覆盖
  if [ -f "$SB_MANUAL_CERTS" ]; then
    local manual
    manual=$(SB_MANUAL_CERTS="$SB_MANUAL_CERTS" python3 -c "
import json, os
try:
    d = json.load(open(os.environ['SB_MANUAL_CERTS']))
    for domain, v in d.items():
        print(domain + chr(1) + v.get('cert','') + chr(1) + v.get('key',''))
except Exception:
    pass")
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      domain=$(echo "$line" | cut -d$'\1' -f1)
      c=$(echo "$line" | cut -d$'\1' -f2)
      k=$(echo "$line" | cut -d$'\1' -f3)
      if [ -f "$c" ] && [ -f "$k" ] && cert_valid_for "$c" "$domain"; then
        CERT_MAP["$domain"]="$c|$k"; CERT_SRC["$domain"]="手动添加"
      fi
    done <<< "$manual"
  fi
  [ ${#CERT_MAP[@]} -gt 0 ] && info "检测到 ${#CERT_MAP[@]} 张可用证书: ${!CERT_MAP[*]}"
}

# $1: 域名 → stdout 输出 "cert_path key_path"
resolve_cert() {
  local domain="$1" entry c k yn choice line
  mkdir -p "$SB_CERTS"
  entry="${CERT_MAP[$domain]:-}"
  if [ -n "$entry" ]; then
    c="${entry%%|*}"; k="${entry##*|}"
    echo "检测到 [$domain] 的现成证书 (${CERT_SRC[$domain]:-})：" >&2
    echo "  证书: $c" >&2
    echo "  私钥: $k" >&2
    read -rp "回车直接使用，n 换其他方式 [Y/n]: " yn
    if [ "${yn:-Y}" != "n" ] && [ "${yn:-Y}" != "N" ]; then
      echo "$c $k"; return 0
    fi
  fi
  echo "证书来源：" >&2
  echo "  1) 手动填写证书文件路径" >&2
  echo "  2) 生成自签证书（客户端需开 insecure）" >&2
  echo "  3) 直接粘贴证书 + 私钥内容" >&2
  read -rp "选择 [1/2/3，默认 2]: " choice
  choice=${choice:-2}
  case "$choice" in
    1)
      read -rp "证书文件路径 (fullchain): " c
      read -rp "私钥文件路径: " k
      if [ ! -f "$c" ] || [ ! -f "$k" ]; then err "文件不存在" >&2; return 1; fi
      echo "$c $k"; return 0 ;;
    3)
      c="$SB_CERTS/${domain}.crt"; k="$SB_CERTS/${domain}.key"
      echo "粘贴证书 PEM 内容（从 -----BEGIN CERTIFICATE----- 开始），结束单独一行输入 EOF：" >&2
      : > "$c"
      while IFS= read -r line; do
        [ "$line" = "EOF" ] && break
        echo "$line" >> "$c"
      done
      echo "粘贴私钥 PEM 内容，结束单独一行输入 EOF：" >&2
      : > "$k"
      while IFS= read -r line; do
        [ "$line" = "EOF" ] && break
        echo "$line" >> "$k"
      done
      chmod 600 "$c" "$k"
      if ! openssl x509 -noout -in "$c" 2>/dev/null; then err "证书内容无效" >&2; return 1; fi
      ok "证书已保存，下次自动检测可识别" >&2
      echo "$c $k"; return 0 ;;
    *)
      need_cmd openssl
      c="$SB_CERTS/${domain}.crt"; k="$SB_CERTS/${domain}.key"
      openssl req -x509 -newkey rsa:2048 -keyout "$k" -out "$c" -days 3650 -nodes \
        -subj "/CN=${domain}" >/dev/null 2>&1
      chmod 600 "$c" "$k"
      echo "$c $k"; return 0 ;;
  esac
}

# ---------- sing-box 安装 ----------
latest_version() {
  local v
  v=$(curl -s --max-time 10 https://api.github.com/repos/SagerNet/sing-box/releases/latest \
      | grep -o '"tag_name": *"v[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -z "$v" ]; then
    warn "GitHub API 获取版本失败，使用内置兜底版本 v1.12.10"
    v="v1.12.10"
  fi
  echo "$v"
}

install_singbox() {
  need_cmd curl; need_cmd tar; need_cmd systemctl
  local arch ver url tmp
  arch=$(detect_arch)
  if [ -x "$SB_BIN" ]; then
    ok "sing-box 已安装: $($SB_BIN version 2>/dev/null | head -1)"
    return 0
  fi
  ver=$(latest_version)
  info "安装 sing-box $ver ($arch) ..."
  url="https://github.com/SagerNet/sing-box/releases/download/${ver}/sing-box-${ver#v}-linux-${arch}.tar.gz"
  tmp=$(mktemp -d)
  curl -L --progress-bar -o "$tmp/sb.tar.gz" "$url" || { err "下载失败"; rm -rf "$tmp"; exit 1; }
  tar xzf "$tmp/sb.tar.gz" -C "$tmp"
  install -m 755 "$tmp/sing-box-${ver#v}-linux-${arch}/sing-box" "$SB_BIN"
  rm -rf "$tmp"
  mkdir -p "$SB_DIR" "$SB_NODES"
  [ -f "$SB_CONF" ] || echo '{"log":{"level":"info"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$SB_CONF"
  cat > "$SB_SERVICE" <<'EOF'
[Unit]
Description=sing-box service
After=network.target nss-lookup.target

[Service]
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable sing-box >/dev/null 2>&1
  enable_bbr v1
  ok "sing-box $ver 安装完成"
}

# ---------- JSON 操作 ----------
json_add_inbound() {
  SB_CONF="$SB_CONF" INBOUND_JSON="$1" python3 - <<'PYEOF'
import json, os
p = os.environ["SB_CONF"]
conf = json.load(open(p))
conf.setdefault("inbounds", []).append(json.loads(os.environ["INBOUND_JSON"]))
json.dump(conf, open(p, "w"), indent=2, ensure_ascii=False)
PYEOF
}

json_del_inbound() {
  SB_CONF="$SB_CONF" DEL_TAG="$1" python3 - <<'PYEOF'
import json, os
p = os.environ["SB_CONF"]
conf = json.load(open(p))
conf["inbounds"] = [i for i in conf.get("inbounds", []) if i.get("tag") != os.environ["DEL_TAG"]]
json.dump(conf, open(p, "w"), indent=2, ensure_ascii=False)
PYEOF
}

# 按 tag 更新 inbound 字段。$1: tag  $2: python 表达式里用的 updates JSON
json_update_inbound() {
  SB_CONF="$SB_CONF" UPD_TAG="$1" UPD_JSON="$2" python3 - <<'PYEOF'
import json, os
p = os.environ["SB_CONF"]
conf = json.load(open(p))
updates = json.loads(os.environ["UPD_JSON"])
def deep_merge(d, u):
    for k, v in u.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            deep_merge(d[k], v)
        else:
            d[k] = v
for i in conf.get("inbounds", []):
    if i.get("tag") == os.environ["UPD_TAG"]:
        deep_merge(i, updates)
json.dump(conf, open(p, "w"), indent=2, ensure_ascii=False)
PYEOF
}

json_list_tags() {
  SB_CONF="$SB_CONF" python3 -c "
import json, os
conf = json.load(open(os.environ['SB_CONF']))
for i in conf.get('inbounds', []):
    print(i.get('tag','') + ' | ' + i.get('type','') + ' | port ' + str(i.get('listen_port','')))"
}

# ---------- 节点元数据 ----------
# 每个节点一份 JSON，供订阅生成和修改节点用
save_node_meta() {
  # $1: tag  $2: 元数据 JSON
  mkdir -p "$SB_NODES"
  echo "$2" | python3 -m json.tool > "$SB_NODES/$1.json"
}

load_node_meta() {
  # $1: tag → 输出元数据 JSON
  cat "$SB_NODES/$1.json" 2>/dev/null
}

list_node_tags() {
  for f in "$SB_NODES"/*.json; do
    [ -f "$f" ] || continue
    basename "$f" .json
  done
}

del_node_meta() { rm -f "$SB_NODES/$1.json"; }

# ---------- 配置校验与重启 ----------
sb_check_restart() {
  local out rc
  out=$("$SB_BIN" check -c "$SB_CONF" 2>&1); rc=$?
  if [ $rc -ne 0 ]; then
    err "配置校验失败："
    echo "$out" | head -10
    return 1
  fi
  systemctl restart sing-box
  sleep 1
  if systemctl is-active -q sing-box; then
    ok "sing-box 运行中"
  else
    err "sing-box 启动失败: journalctl -u sing-box -n 30"
    return 1
  fi
}

print_qr() {
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 "$1"
  else
    warn "未安装 qrencode，跳过二维码 (apt install qrencode)"
  fi
}

# ---------- 通用 ----------
QUIET=0  # CLI 模式置 1，全自动不提问

is_self_signed() {
  local iss sub
  iss=$(openssl x509 -noout -in "$1" -issuer 2>/dev/null)
  sub=$(openssl x509 -noout -in "$1" -subject 2>/dev/null)
  [ -n "$iss" ] && [ "$iss" = "$sub" ]
}

# 收集客户端链接用的地址列表。$1: addr_mode(1=v4 2=v6 3=都要) → 设置 HOSTS 数组
collect_hosts() {
  HOSTS=()
  local h4 h6
  h4=$(get_public_ip "$QUIET" 2>/dev/null)
  h6=$(get_public_ip6 2>/dev/null)
  case "${1:-3}" in
    1) [ -n "$h4" ] && HOSTS+=("$h4") ;;
    2) [ -n "$h6" ] && HOSTS+=("[$h6]") ;;
    *) [ -n "$h4" ] && HOSTS+=("$h4"); [ -n "$h6" ] && HOSTS+=("[$h6]") ;;
  esac
  if [ ${#HOSTS[@]} -eq 0 ]; then err "没有可用的公网地址"; return 1; fi
}

show_links() {
  local name="$1"; shift
  echo ""; ok "$name 添加成功"
  local l
  for l in "$@"; do echo "$l"; print_qr "$l"; done
}

# 统一收尾：写元数据 → 校验重启（失败回滚）→ 重建订阅
# $1: tag  $2: 元数据JSON  $3: 展示名  $4..: 链接
finish_add() {
  local tag="$1" meta="$2" name="$3"; shift 3
  local links_json
  links_json=$(printf '%s\n' "$@" | python3 -c "import json,sys; print(json.dumps([l for l in sys.stdin.read().splitlines() if l]))")
  meta=$(echo "$meta" | SB_LINKS="$links_json" python3 -c "
import json, os, sys
m = json.load(sys.stdin)
m['links'] = json.loads(os.environ['SB_LINKS'])
print(json.dumps(m, ensure_ascii=False))")
  save_node_meta "$tag" "$meta"
  json_add_inbound "$PENDING_INBOUND"
  if ! sb_check_restart; then
    json_del_inbound "$tag"; del_node_meta "$tag"
    err "已回滚"
    return 1
  fi
  build_subscriptions 2>/dev/null || warn "订阅重建失败，可稍后手动重建"
  show_links "$name" "$@"
}

# ---------- 1. VLESS + REALITY ----------
add_reality() {
  local port="${1:-}" domain="${2:-}"
  local uuid keypair priv pub shortid tag host mode links=() h
  info "添加 VLESS + REALITY"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && { port=443; port_in_use "$port" && port=$(random_port); }
    ensure_port_free "$port" || return 1
    [ -z "$domain" ] && domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
    uuid=$("$SB_BIN" generate uuid); mode=3
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "REALITY"); fi
    if [ -z "$domain" ]; then
      domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
      info "随机伪装域名: $domain (如需指定下次用 --domain)"
    fi
    uuid=$(ask_uuid); mode=$(ask_addr_mode)
  fi
  keypair=$("$SB_BIN" generate reality-keypair)
  priv=$(echo "$keypair" | grep -i private | awk '{print $NF}')
  pub=$(echo "$keypair" | grep -i public | awk '{print $NF}')
  shortid=$(openssl rand -hex 8)
  tag="reality-${port}"
  collect_hosts "$mode" || return 1

  PENDING_INBOUND=$(cat <<EOF
{"type":"vless","tag":"$tag","listen":"::","listen_port":$port,
 "users":[{"uuid":"$uuid","flow":"xtls-rprx-vision"}],
 "tls":{"enabled":true,"server_name":"$domain",
  "reality":{"enabled":true,"handshake":{"server":"$domain","server_port":443},
   "private_key":"$priv","short_id":["$shortid"]}}}
EOF
)
  for h in "${HOSTS[@]}"; do
    links+=("vless://${uuid}@${h}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${domain}&fp=chrome&pbk=${pub}&sid=${shortid}&type=tcp#REALITY-${port}")
  done
  local meta
  meta=$(cat <<EOF
{"tag":"$tag","proto":"vless-reality","name":"REALITY-${port}","port":$port,
 "uuid":"$uuid","password":null,"domain":"$domain","path":null,
 "pubkey":"$pub","shortid":"$shortid","cert":null,"key":null,"selfsigned":false,
 "hosts":$(printf '%s\n' "${HOSTS[@]}" | python3 -c "import json,sys;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "VLESS+REALITY" "${links[@]}"
}

# ---------- 2. VLESS + WS + TLS ----------
add_ws_tls() {
  local port="${1:-}" domain="${2:-}" cert="${3:-}" key="${4:-}"
  local uuid path tag mode links=() h c k
  info "添加 VLESS + WS + TLS"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && { port=443; port_in_use "$port" && port=$(random_port); }
    ensure_port_free "$port" || return 1
    [ -z "$domain" ] && { err "CLI 模式需要 --domain"; return 1; }
    [ -z "$cert" ] || [ -z "$key" ] && { err "CLI 模式需要 --cert 和 --key"; return 1; }
    uuid=$("$SB_BIN" generate uuid); mode=3; c="$cert"; k="$key"
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "VLESS/WS/TLS"); fi
    [ -z "$domain" ] && domain=$(ask_domain "")
    [ -z "$domain" ] && { err "域名不能为空"; return 1; }
    if [ -z "$cert" ]; then
      read -r c k <<< "$(resolve_cert "$domain")" || return 1
    else c="$cert"; k="$key"; fi
    uuid=$(ask_uuid); mode=$(ask_addr_mode)
  fi
  path="/$(openssl rand -hex 6)"
  tag="ws-tls-${port}"
  collect_hosts "$mode" || return 1

  PENDING_INBOUND=$(cat <<EOF
{"type":"vless","tag":"$tag","listen":"::","listen_port":$port,
 "users":[{"uuid":"$uuid"}],
 "transport":{"type":"ws","path":"$path"},
 "tls":{"enabled":true,"server_name":"$domain","certificate_path":"$c","key_path":"$k"}}
EOF
)
  local enc_path=${path//\//%2F}
  for h in "${HOSTS[@]}"; do
    links+=("vless://${uuid}@${h}:${port}?encryption=none&security=tls&sni=${domain}&type=ws&path=${enc_path}&host=${domain}#WS-TLS-${port}")
  done
  local meta
  meta=$(cat <<EOF
{"tag":"$tag","proto":"vless-ws-tls","name":"WS-TLS-${port}","port":$port,
 "uuid":"$uuid","password":null,"domain":"$domain","path":"$path",
 "pubkey":null,"shortid":null,"cert":"$c","key":"$k","selfsigned":false,
 "hosts":$(printf '%s\n' "${HOSTS[@]}" | python3 -c "import json,sys;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "VLESS+WS+TLS" "${links[@]}"
}

# ---------- 3. VLESS + WS (明文) ----------
add_ws() {
  local port="${1:-}"
  local uuid path tag mode links=() h
  info "添加 VLESS + WS (明文无 TLS，一般配合 CDN/反代使用)"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && port=$(random_port)
    ensure_port_free "$port" || return 1
    uuid=$("$SB_BIN" generate uuid); mode=3
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "VLESS/WS"); fi
    uuid=$(ask_uuid); mode=$(ask_addr_mode)
  fi
  path="/$(openssl rand -hex 6)"
  tag="ws-${port}"
  collect_hosts "$mode" || return 1

  PENDING_INBOUND=$(cat <<EOF
{"type":"vless","tag":"$tag","listen":"::","listen_port":$port,
 "users":[{"uuid":"$uuid"}],
 "transport":{"type":"ws","path":"$path"}}
EOF
)
  local enc_path=${path//\//%2F}
  for h in "${HOSTS[@]}"; do
    links+=("vless://${uuid}@${h}:${port}?encryption=none&type=ws&path=${enc_path}&security=none#WS-${port}")
  done
  local meta
  meta=$(cat <<EOF
{"tag":"$tag","proto":"vless-ws","name":"WS-${port}","port":$port,
 "uuid":"$uuid","password":null,"domain":null,"path":"$path",
 "pubkey":null,"shortid":null,"cert":null,"key":null,"selfsigned":false,
 "hosts":$(printf '%s\n' "${HOSTS[@]}" | python3 -c "import json,sys;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "VLESS+WS" "${links[@]}"
}

# ---------- 4. TUIC v5 ----------
add_tuic() {
  local port="${1:-}"
  local uuid passwd tag mode links=() h c k insecure domain
  info "添加 TUIC v5"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && port=$(random_port)
    ensure_port_free "$port" || return 1
    domain="bing.com"; c=""; k=""
    uuid=$("$SB_BIN" generate uuid); passwd=$(openssl rand -hex 12); mode=3
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "TUIC"); fi
    domain=$(ask_domain "bing.com")
    read -r c k <<< "$(resolve_cert "$domain")" || return 1
    uuid=$(ask_uuid); passwd=$(ask_password); mode=$(ask_addr_mode)
  fi
  if [ -z "$c" ]; then
    # QUIET 模式无证书时现场自签
    c="$SB_CERTS/tuic-${port}.crt"; k="$SB_CERTS/tuic-${port}.key"
    mkdir -p "$SB_CERTS"
    openssl req -x509 -newkey rsa:2048 -keyout "$k" -out "$c" -days 3650 -nodes \
      -subj "/CN=${domain}" >/dev/null 2>&1
    chmod 600 "$c" "$k"
  fi
  is_self_signed "$c" && insecure="&allow_insecure=1" || insecure=""
  [ -n "$insecure" ] && warn "自签证书：客户端需开启 allow_insecure"
  tag="tuic-${port}"
  collect_hosts "$mode" || return 1

  PENDING_INBOUND=$(cat <<EOF
{"type":"tuic","tag":"$tag","listen":"::","listen_port":$port,
 "users":[{"uuid":"$uuid","password":"$passwd"}],
 "congestion_control":"bbr",
 "tls":{"enabled":true,"server_name":"$domain","alpn":["h3"],
  "certificate_path":"$c","key_path":"$k"}}
EOF
)
  for h in "${HOSTS[@]}"; do
    links+=("tuic://${uuid}:${passwd}@${h}:${port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=${domain}${insecure}#TUIC-${port}")
  done
  local meta selfsigned=false
  is_self_signed "$c" && selfsigned=true
  meta=$(cat <<EOF
{"tag":"$tag","proto":"tuic","name":"TUIC-${port}","port":$port,
 "uuid":"$uuid","password":"$passwd","domain":"$domain","path":null,
 "pubkey":null,"shortid":null,"cert":"$c","key":"$k","selfsigned":$selfsigned,
 "hosts":$(printf '%s\n' "${HOSTS[@]}" | python3 -c "import json,sys;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "TUIC" "${links[@]}"
}

# ---------- 5. Hysteria2 ----------
add_hy2() {
  local port="${1:-}"
  local passwd tag mode links=() h c k insecure domain
  info "添加 Hysteria2"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && port=$(random_port)
    ensure_port_free "$port" || return 1
    domain="bing.com"; c=""; k=""
    passwd=$(openssl rand -hex 16); mode=3
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "Hysteria2"); fi
    domain=$(ask_domain "bing.com")
    read -r c k <<< "$(resolve_cert "$domain")" || return 1
    passwd=$(ask_password); mode=$(ask_addr_mode)
  fi
  if [ -z "$c" ]; then
    c="$SB_CERTS/hy2-${port}.crt"; k="$SB_CERTS/hy2-${port}.key"
    mkdir -p "$SB_CERTS"
    openssl req -x509 -newkey rsa:2048 -keyout "$k" -out "$c" -days 3650 -nodes \
      -subj "/CN=${domain}" >/dev/null 2>&1
    chmod 600 "$c" "$k"
  fi
  is_self_signed "$c" && insecure="&insecure=1" || insecure=""
  [ -n "$insecure" ] && warn "自签证书：客户端需开启 insecure"
  tag="hy2-${port}"
  collect_hosts "$mode" || return 1

  PENDING_INBOUND=$(cat <<EOF
{"type":"hysteria2","tag":"$tag","listen":"::","listen_port":$port,
 "users":[{"password":"$passwd"}],
 "tls":{"enabled":true,"server_name":"$domain","alpn":["h3"],
  "certificate_path":"$c","key_path":"$k"}}
EOF
)
  for h in "${HOSTS[@]}"; do
    links+=("hysteria2://${passwd}@${h}:${port}?sni=${domain}${insecure}#HY2-${port}")
  done
  local meta selfsigned=false
  is_self_signed "$c" && selfsigned=true
  meta=$(cat <<EOF
{"tag":"$tag","proto":"hy2","name":"HY2-${port}","port":$port,
 "uuid":null,"password":"$passwd","domain":"$domain","path":null,
 "pubkey":null,"shortid":null,"cert":"$c","key":"$k","selfsigned":$selfsigned,
 "hosts":$(printf '%s\n' "${HOSTS[@]}" | python3 -c "import json,sys;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "Hysteria2" "${links[@]}"
}

# ---------- 6. AnyTLS ----------
add_anytls() {
  local port="${1:-}"
  local passwd tag mode links=() h c k insecure domain
  info "添加 AnyTLS"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && port=$(random_port)
    ensure_port_free "$port" || return 1
    domain="bing.com"; c=""; k=""
    passwd=$(openssl rand -hex 16); mode=3
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "AnyTLS"); fi
    domain=$(ask_domain "bing.com")
    read -r c k <<< "$(resolve_cert "$domain")" || return 1
    passwd=$(ask_password); mode=$(ask_addr_mode)
  fi
  if [ -z "$c" ]; then
    c="$SB_CERTS/anytls-${port}.crt"; k="$SB_CERTS/anytls-${port}.key"
    mkdir -p "$SB_CERTS"
    openssl req -x509 -newkey rsa:2048 -keyout "$k" -out "$c" -days 3650 -nodes \
      -subj "/CN=${domain}" >/dev/null 2>&1
    chmod 600 "$c" "$k"
  fi
  is_self_signed "$c" && insecure="&insecure=1" || insecure=""
  [ -n "$insecure" ] && warn "自签证书：客户端需开启 insecure"
  tag="anytls-${port}"
  collect_hosts "$mode" || return 1

  PENDING_INBOUND=$(cat <<EOF
{"type":"anytls","tag":"$tag","listen":"::","listen_port":$port,
 "users":[{"password":"$passwd"}],
 "tls":{"enabled":true,"server_name":"$domain",
  "certificate_path":"$c","key_path":"$k"}}
EOF
)
  for h in "${HOSTS[@]}"; do
    links+=("anytls://${passwd}@${h}:${port}?sni=${domain}${insecure}#AnyTLS-${port}")
  done
  local meta selfsigned=false
  is_self_signed "$c" && selfsigned=true
  meta=$(cat <<EOF
{"tag":"$tag","proto":"anytls","name":"AnyTLS-${port}","port":$port,
 "uuid":null,"password":"$passwd","domain":"$domain","path":null,
 "pubkey":null,"shortid":null,"cert":"$c","key":"$k","selfsigned":$selfsigned,
 "hosts":$(printf '%s\n' "${HOSTS[@]}" | python3 -c "import json,sys;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"),
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "AnyTLS" "${links[@]}"
}

# ---------- 一键搭建：零交互，直接出 REALITY 节点 ----------
onekey() {
  info "一键搭建模式：全自动创建 VLESS+REALITY 节点"
  QUIET=1
  install_singbox
  detect_certs
  add_reality "" ""
}

# ---------- 订阅系统 ----------
# 三种格式：v2rayn(base64) / clash.yaml / singbox.json
# 存放：$SB_SUB/<token>/

build_subscriptions() {
  local token subdir
  mkdir -p "$SB_SUB"
  if [ -f "$SB_DIR/sub-token" ]; then
    token=$(cat "$SB_DIR/sub-token")
  else
    token=$(openssl rand -hex 8)
    echo "$token" > "$SB_DIR/sub-token"
  fi
  subdir="$SB_SUB/$token"
  mkdir -p "$subdir"
  SB_NODES="$SB_NODES" SUBDIR="$subdir" python3 - <<'PYEOF'
import json, os, glob, base64

nodes = []
for f in sorted(glob.glob(os.path.join(os.environ["SB_NODES"], "*.json"))):
    try:
        nodes.append(json.load(open(f)))
    except Exception:
        pass
subdir = os.environ["SUBDIR"]

def gen_links(n):
    links = []
    for h in n.get("hosts", []):
        port, name = n["port"], n["name"]
        p = n["proto"]
        if p == "vless-reality":
            links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={n['domain']}&fp=chrome&pbk={n['pubkey']}&sid={n['shortid']}&type=tcp#{name}")
        elif p == "vless-ws-tls":
            path = n["path"].replace("/", "%2F")
            links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&security=tls&sni={n['domain']}&type=ws&path={path}&host={n['domain']}#{name}")
        elif p == "vless-ws":
            path = n["path"].replace("/", "%2F")
            links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&type=ws&path={path}&security=none#{name}")
        elif p == "tuic":
            ins = "&allow_insecure=1" if n.get("selfsigned") else ""
            links.append(f"tuic://{n['uuid']}:{n['password']}@{h}:{port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni={n['domain']}{ins}#{name}")
        elif p == "hy2":
            ins = "&insecure=1" if n.get("selfsigned") else ""
            links.append(f"hysteria2://{n['password']}@{h}:{port}?sni={n['domain']}{ins}#{name}")
        elif p == "anytls":
            ins = "&insecure=1" if n.get("selfsigned") else ""
            links.append(f"anytls://{n['password']}@{h}:{port}?sni={n['domain']}{ins}#{name}")
    return links

def bare_host(h):
    return h[1:-1] if h.startswith("[") else h

# 1) v2rayN：分享链接 base64
all_links = []
for n in nodes:
    all_links.extend(gen_links(n))
with open(os.path.join(subdir, "v2rayn"), "w") as f:
    f.write(base64.b64encode("\n".join(all_links).encode()).decode())

# 2) clash.yaml
L = []
L.append("proxies:")
for n in nodes:
    h = bare_host(n["hosts"][0])
    port, name = n["port"], n["name"]
    p = n["proto"]
    skip = "true" if n.get("selfsigned") else "false"
    if p == "vless-reality":
        L.append(f"""- name: "{name}"
  type: vless
  server: {h}
  port: {port}
  uuid: {n['uuid']}
  udp: true
  tls: true
  network: tcp
  flow: xtls-rprx-vision
  servername: {n['domain']}
  client-fingerprint: chrome
  reality-opts:
    public-key: {n['pubkey']}
    short-id: {n['shortid']}""")
    elif p in ("vless-ws-tls", "vless-ws"):
        tls = "true" if p == "vless-ws-tls" else "false"
        sn = f"\n  servername: {n['domain']}" if p == "vless-ws-tls" else ""
        host_h = f"\n      Host: {n['domain']}" if p == "vless-ws-tls" else ""
        L.append(f"""- name: "{name}"
  type: vless
  server: {h}
  port: {port}
  uuid: {n['uuid']}
  udp: true
  tls: {tls}
  network: ws{sn}
  ws-opts:
    path: {n['path']}{host_h}""")
    elif p == "tuic":
        L.append(f"""- name: "{name}"
  type: tuic
  server: {h}
  port: {port}
  uuid: {n['uuid']}
  password: {n['password']}
  alpn: [h3]
  sni: {n['domain']}
  skip-cert-verify: {skip}
  congestion-controller: bbr
  udp-relay-mode: native""")
    elif p == "hy2":
        L.append(f"""- name: "{name}"
  type: hysteria2
  server: {h}
  port: {port}
  password: {n['password']}
  sni: {n['domain']}
  skip-cert-verify: {skip}""")
    elif p == "anytls":
        L.append(f"""- name: "{name}"
  type: anytls
  server: {h}
  port: {port}
  password: {n['password']}
  sni: {n['domain']}
  skip-cert-verify: {skip}""")
L.append("")
L.append("proxy-groups:")
L.append("  - name: 手动选择")
L.append("    type: select")
L.append("    proxies:")
for n in nodes:
    L.append(f'      - "{n["name"]}"')
with open(os.path.join(subdir, "clash.yaml"), "w") as f:
    f.write("\n".join(L) + "\n")

# 3) singbox.json
outbounds = []
for n in nodes:
    h = bare_host(n["hosts"][0])
    port = n["port"]
    p = n["proto"]
    if p == "vless-reality":
        outbounds.append({"type": "vless", "tag": n["name"], "server": h, "server_port": port,
            "uuid": n["uuid"], "flow": "xtls-rprx-vision",
            "tls": {"enabled": True, "server_name": n["domain"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": n["pubkey"], "short_id": n["shortid"]}}})
    elif p == "vless-ws-tls":
        outbounds.append({"type": "vless", "tag": n["name"], "server": h, "server_port": port,
            "uuid": n["uuid"],
            "transport": {"type": "ws", "path": n["path"], "headers": {"Host": n["domain"]}},
            "tls": {"enabled": True, "server_name": n["domain"],
                "insecure": bool(n.get("selfsigned"))}})
    elif p == "vless-ws":
        outbounds.append({"type": "vless", "tag": n["name"], "server": h, "server_port": port,
            "uuid": n["uuid"], "transport": {"type": "ws", "path": n["path"]}})
    elif p == "tuic":
        outbounds.append({"type": "tuic", "tag": n["name"], "server": h, "server_port": port,
            "uuid": n["uuid"], "password": n["password"],
            "congestion_control": "bbr", "udp_relay_mode": "native",
            "tls": {"enabled": True, "server_name": n["domain"], "alpn": ["h3"],
                "insecure": bool(n.get("selfsigned"))}})
    elif p == "hy2":
        outbounds.append({"type": "hysteria2", "tag": n["name"], "server": h, "server_port": port,
            "password": n["password"],
            "tls": {"enabled": True, "server_name": n["domain"], "alpn": ["h3"],
                "insecure": bool(n.get("selfsigned"))}})
    elif p == "anytls":
        outbounds.append({"type": "anytls", "tag": n["name"], "server": h, "server_port": port,
            "password": n["password"],
            "tls": {"enabled": True, "server_name": n["domain"],
                "insecure": bool(n.get("selfsigned"))}})
with open(os.path.join(subdir, "singbox.json"), "w") as f:
    json.dump({"outbounds": outbounds}, f, indent=2, ensure_ascii=False)
print(f"订阅已生成：{len(nodes)} 个节点")
PYEOF
}

sub_urls() {
  # 输出订阅 URL（需订阅服务运行）
  local token port h4
  [ -f "$SB_DIR/sub-token" ] || { warn "订阅尚未生成"; return 1; }
  token=$(cat "$SB_DIR/sub-token")
  port=$(cat "$SB_DIR/sub-port" 2>/dev/null)
  [ -z "$port" ] && { warn "订阅服务未启动"; return 1; }
  h4=$(get_public_ip 1 2>/dev/null)
  [ -z "$h4" ] && { err "无法获取公网 IP"; return 1; }
  echo "v2rayN : http://${h4}:${port}/${token}/v2rayn"
  echo "Clash  : http://${h4}:${port}/${token}/clash.yaml"
  echo "sing-box: http://${h4}:${port}/${token}/singbox.json"
}

sub_server_start() {
  local port token
  if systemctl is-active -q sing-box-sub 2>/dev/null; then
    ok "订阅服务已在运行"; sub_urls; return 0
  fi
  port=$(cat "$SB_DIR/sub-port" 2>/dev/null)
  if [ -z "$port" ] || port_in_use "$port"; then
    port=$(random_port) || return 1
    echo "$port" > "$SB_DIR/sub-port"
  fi
  token=$(cat "$SB_DIR/sub-token" 2>/dev/null)
  [ -z "$token" ] && build_subscriptions
  mkdir -p "$SB_SUB"
  cat > "$SB_SUB_SERVICE" <<EOF
[Unit]
Description=sing-box subscription server
After=network.target

[Service]
User=root
ExecStart=/usr/bin/python3 -m http.server ${port} --directory ${SB_SUB}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now sing-box-sub
  sleep 1
  if systemctl is-active -q sing-box-sub; then
    ok "订阅服务已启动"
    sub_urls
    warn "HTTP 明文传输含节点凭证，同步完建议关闭"
  else
    err "订阅服务启动失败"
    return 1
  fi
}

sub_server_stop() {
  systemctl stop sing-box-sub 2>/dev/null || true
  systemctl disable sing-box-sub 2>/dev/null || true
  rm -f "$SB_SUB_SERVICE"
  systemctl daemon-reload
  ok "订阅服务已停止"
}

show_subscriptions() {
  local token subdir
  [ -f "$SB_DIR/sub-token" ] || build_subscriptions
  token=$(cat "$SB_DIR/sub-token")
  subdir="$SB_SUB/$token"
  echo "===== 订阅文件 ($subdir) ====="
  ls -la "$subdir" 2>/dev/null
  echo ""
  echo "----- v2rayN (base64，前200字符) -----"
  head -c 200 "$subdir/v2rayn" 2>/dev/null; echo ""
  echo ""
  echo "----- clash.yaml -----"
  cat "$subdir/clash.yaml" 2>/dev/null | head -40
  echo ""
  if systemctl is-active -q sing-box-sub 2>/dev/null; then
    echo "----- 订阅 URL -----"
    sub_urls
  else
    warn "订阅服务未启动，URL 不可用（菜单 6 可启动）"
  fi
}

# ---------- 节点管理 ----------
pick_node() {
  # 选择节点 → 输出 tag
  local tags i=1 t n
  mapfile -t tags < <(list_node_tags)
  [ ${#tags[@]} -eq 0 ] && { warn "还没有节点"; return 1; }
  for t in "${tags[@]}"; do
    n=$(python3 -c "import json;print(json.load(open('$SB_NODES/$t.json')).get('name',''))" 2>/dev/null)
    echo "  $((i++)). $t ($n)"
  done
  n=$(read_choice "选择 (序号): ")
  t=${tags[$((n-1))]:-}
  [ -z "$t" ] && { warn "无效序号"; return 1; }
  echo "$t"
}

regen_node_links() {
  # $1: tag → 根据元数据重新生成 links 并写回
  SB_NODES="$SB_NODES" RETAG="$1" python3 - <<'PYEOF'
import json, os, glob
p = os.path.join(os.environ["SB_NODES"], os.environ["RETAG"] + ".json")
n = json.load(open(p))
links = []
for h in n.get("hosts", []):
    port, name = n["port"], n["name"]
    q = n["proto"]
    if q == "vless-reality":
        links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={n['domain']}&fp=chrome&pbk={n['pubkey']}&sid={n['shortid']}&type=tcp#{name}")
    elif q == "vless-ws-tls":
        path = n["path"].replace("/", "%2F")
        links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&security=tls&sni={n['domain']}&type=ws&path={path}&host={n['domain']}#{name}")
    elif q == "vless-ws":
        path = n["path"].replace("/", "%2F")
        links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&type=ws&path={path}&security=none#{name}")
    elif q == "tuic":
        ins = "&allow_insecure=1" if n.get("selfsigned") else ""
        links.append(f"tuic://{n['uuid']}:{n['password']}@{h}:{port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni={n['domain']}{ins}#{name}")
    elif q == "hy2":
        ins = "&insecure=1" if n.get("selfsigned") else ""
        links.append(f"hysteria2://{n['password']}@{h}:{port}?sni={n['domain']}{ins}#{name}")
    elif q == "anytls":
        ins = "&insecure=1" if n.get("selfsigned") else ""
        links.append(f"anytls://{n['password']}@{h}:{port}?sni={n['domain']}{ins}#{name}")
n["links"] = links
json.dump(n, open(p, "w"), indent=2, ensure_ascii=False)
print("\n".join(links))
PYEOF
}

update_node_field() {
  # $1: tag  $2: 字段  $3: 新值 → 更新元数据 JSON
  SB_NODES="$SB_NODES" UFTAG="$1" UFFIELD="$2" UFVAL="$3" python3 - <<'PYEOF'
import json, os
p = os.path.join(os.environ["SB_NODES"], os.environ["UFTAG"] + ".json")
n = json.load(open(p))
v = os.environ["UFVAL"]
f = os.environ["UFFIELD"]
n[f] = int(v) if f == "port" else v
json.dump(n, open(p, "w"), indent=2, ensure_ascii=False)
PYEOF
}

modify_node() {
  local tag field newval proto
  tag=$(pick_node) || return 1
  proto=$(python3 -c "import json;print(json.load(open('$SB_NODES/$tag.json'))['proto'])")
  echo "修改 [$tag]："
  echo "  1) 端口"
  echo "  2) UUID"
  echo "  3) 密码"
  echo "  4) 备注名"
  echo "  5) 域名/sni"
  field=$(read_choice "选择: ")
  cp "$SB_CONF" "$SB_CONF.bak"
  case "$field" in
    1)
      newval=$(ask_port "新端口")
      json_update_inbound "$tag" "{\"listen_port\": $newval}"
      update_node_field "$tag" "port" "$newval"
      # tag 里带端口的同步改名
      local newtag="${tag%-*}-${newval}"
      if [ "$newtag" != "$tag" ]; then
        json_update_inbound "$tag" "{\"tag\": \"$newtag\"}"
        update_node_field "$tag" "tag" "$newtag"
        update_node_field "$tag" "name" "$(python3 -c "import json;print(json.load(open('$SB_NODES/$tag.json'))['name'])" | sed "s/-[0-9]*\$/-$newval/")"
        mv "$SB_NODES/$tag.json" "$SB_NODES/$newtag.json"
        tag="$newtag"
      fi ;;
    2)
      newval=$(ask_uuid)
      json_update_inbound "$tag" "{\"users\": [{\"uuid\": \"$newval\"}]}"
      # 注意：tuic 的 users 含 password，需保留
      if [ "$proto" = "tuic" ]; then
        local pw
        pw=$(python3 -c "import json;print(json.load(open('$SB_NODES/$tag.json'))['password'])")
        json_update_inbound "$tag" "{\"users\": [{\"uuid\": \"$newval\", \"password\": \"$pw\"}]}"
      fi
      update_node_field "$tag" "uuid" "$newval" ;;
    3)
      newval=$(ask_password)
      if [ "$proto" = "tuic" ]; then
        local uuid
        uuid=$(python3 -c "import json;print(json.load(open('$SB_NODES/$tag.json'))['uuid'])")
        json_update_inbound "$tag" "{\"users\": [{\"uuid\": \"$uuid\", \"password\": \"$newval\"}]}"
      else
        json_update_inbound "$tag" "{\"users\": [{\"password\": \"$newval\"}]}"
      fi
      update_node_field "$tag" "password" "$newval" ;;
    4)
      read -rp "新备注名: " newval
      [ -z "$newval" ] && { warn "备注名不能为空"; return 1; }
      update_node_field "$tag" "name" "$newval" ;;
    5)
      newval=$(ask_domain "")
      [ -z "$newval" ] && { warn "域名不能为空"; return 1; }
      if [ "$proto" = "vless-reality" ]; then
        json_update_inbound "$tag" "{\"tls\": {\"server_name\": \"$newval\", \"reality\": {\"handshake\": {\"server\": \"$newval\"}}}}"
      else
        json_update_inbound "$tag" "{\"tls\": {\"server_name\": \"$newval\"}}"
      fi
      update_node_field "$tag" "domain" "$newval"
      # TLS 类协议换域名后重新解析证书
      if [[ "$proto" == "tuic" || "$proto" == "hy2" || "$proto" == "anytls" || "$proto" == "vless-ws-tls" ]]; then
        local c k selfsigned=false
        read -r c k <<< "$(resolve_cert "$newval")" || { cp "$SB_CONF.bak" "$SB_CONF"; err "已回滚"; return 1; }
        json_update_inbound "$tag" "{\"tls\": {\"certificate_path\": \"$c\", \"key_path\": \"$k\"}}"
        update_node_field "$tag" "cert" "$c"; update_node_field "$tag" "key" "$k"
        is_self_signed "$c" && selfsigned=true
        SB_NODES="$SB_NODES" UFTAG="$tag" python3 -c "
import json, os
p = os.path.join(os.environ['SB_NODES'], os.environ['UFTAG'] + '.json')
n = json.load(open(p)); n['selfsigned'] = True if '$selfsigned' == 'true' else False
json.dump(n, open(p, 'w'), indent=2, ensure_ascii=False)"
      fi ;;
    *) warn "无效选择"; return 1 ;;
  esac
  if sb_check_restart; then
    regen_node_links "$tag" | while read -r l; do [ -n "$l" ] && echo "$l"; done
    build_subscriptions 2>/dev/null || true
    ok "修改完成，旧链接已失效"
  else
    cp "$SB_CONF.bak" "$SB_CONF"; systemctl restart sing-box
    err "修改后校验失败，已回滚"
  fi
}

delete_node() {
  local tag yn
  tag=$(pick_node) || return 1
  read -rp "确认删除 [$tag]？(y/n): " yn
  [ "$yn" = "y" ] || return 0
  cp "$SB_CONF" "$SB_CONF.bak"
  json_del_inbound "$tag"
  del_node_meta "$tag"
  if sb_check_restart; then
    build_subscriptions 2>/dev/null || true
    ok "已删除 $tag"
  else
    cp "$SB_CONF.bak" "$SB_CONF"; systemctl restart sing-box
    err "删除后校验失败，已回滚"
  fi
}

show_nodes() {
  echo "===== 入站列表 ====="
  if [ -f "$SB_CONF" ]; then json_list_tags; else warn "尚未安装"; fi
  echo ""
  local t
  for t in $(list_node_tags); do
    echo "----- $t -----"
    python3 -c "
import json
n = json.load(open('$SB_NODES/$t.json'))
for k in ('name','proto','port','domain','path','created'):
    v = n.get(k)
    if v: print(f'{k}: {v}')
for l in n.get('links', []): print(l)"
    echo ""
  done
}

# ---------- 证书管理 ----------
cert_menu() {
  while :; do
    echo ""
    _cyan "===== 证书管理 ====="
    echo "  1. 查看证书列表"
    echo "  2. 添加证书（域名+路径）"
    echo "  3. 删除证书"
    echo "  0. 返回"
    n=$(read_choice "选择: ")
    [ -z "$n" ] && return
    case "$n" in
      1)
        detect_certs
        if [ ${#CERT_MAP[@]} -eq 0 ]; then warn "没有可用证书"; continue; fi
        printf "%-30s %-12s %s\n" "域名" "来源" "有效期至"
        local d
        for d in "${!CERT_MAP[@]}"; do
          printf "%-30s %-12s %s\n" "$d" "${CERT_SRC[$d]}" "$(cert_expiry "${CERT_MAP[$d]%%|*}")"
        done ;;
      2)
        local domain c k
        read -rp "域名: " domain
        [ -z "$domain" ] && { warn "域名不能为空"; continue; }
        read -rp "证书文件路径 (fullchain): " c
        read -rp "私钥文件路径: " k
        if [ ! -f "$c" ] || [ ! -f "$k" ]; then err "文件不存在"; continue; fi
        if ! cert_valid_for "$c" "$domain"; then
          err "校验失败：证书过期或与域名 $domain 不匹配"
          continue
        fi
        mkdir -p "$SB_DIR"
        SB_MANUAL_CERTS="$SB_MANUAL_CERTS" MC_DOMAIN="$domain" MC_CERT="$c" MC_KEY="$k" python3 - <<'PYEOF'
import json, os
p = os.environ["SB_MANUAL_CERTS"]
try:
    d = json.load(open(p))
except Exception:
    d = {}
d[os.environ["MC_DOMAIN"]] = {"cert": os.environ["MC_CERT"], "key": os.environ["MC_KEY"]}
json.dump(d, open(p, "w"), indent=2, ensure_ascii=False)
PYEOF
        ok "证书已添加 [$domain]" ;;
      3)
        if [ ! -f "$SB_MANUAL_CERTS" ]; then warn "没有手动添加的证书"; continue; fi
        local domains i=1 d sel
        mapfile -t domains < <(python3 -c "import json;print('\n'.join(json.load(open('$SB_MANUAL_CERTS')).keys()))")
        [ ${#domains[@]} -eq 0 ] && { warn "没有手动添加的证书"; continue; }
        for d in "${domains[@]}"; do echo "  $((i++)). $d"; done
        read -rp "删除哪个 (序号): " sel
        d=${domains[$((sel-1))]:-}
        [ -z "$d" ] && { warn "无效序号"; continue; }
        SB_MANUAL_CERTS="$SB_MANUAL_CERTS" MC_DOMAIN="$d" python3 -c "
import json, os
p = os.environ['SB_MANUAL_CERTS']
d = json.load(open(p)); d.pop(os.environ['MC_DOMAIN'], None)
json.dump(d, open(p, 'w'), indent=2, ensure_ascii=False)"
        ok "已删除 [$d]" ;;
      0) return ;;
      *) warn "无效选择" ;;
    esac
  done
}

# ---------- BBR / BBRv3 ----------
enable_bbr() {
  # $1: 版本说明（仅提示用）
  if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    ok "BBR 已启用"
    return 0
  fi
  info "开启 BBR ..."
  mkdir -p /etc/sysctl.d
  echo "net.core.default_qdisc=fq" > /etc/sysctl.d/99-singbox-bbr.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-singbox-bbr.conf
  sysctl -p /etc/sysctl.d/99-singbox-bbr.conf >/dev/null 2>&1 || true
  ok "BBR 已启用"
}

bbr_status() {
  echo "内核: $(uname -r)"
  echo "当前拥塞算法: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
  echo "可用算法: $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)"
  if uname -r | grep -q xanmod; then
    echo "BBRv3: 可用（XanMod 内核默认即 BBRv3）"
  else
    echo "BBRv3: 不可用（主线内核仅带 BBR v1，需换 XanMod 内核）"
  fi
}

install_xanmod() {
  local flags variant yn
  warn "安装 XanMod 内核后需要重启才能生效，旧内核会保留"
  warn "VPS（KVM 架构）一般没问题，但生产机请三思"
  read -rp "继续？(y/n): " yn
  [ "$yn" = "y" ] || return 0
  flags=$(grep -m1 flags /proc/cpuinfo)
  if echo "$flags" | grep -qw avx2 && echo "$flags" | grep -qw bmi2; then
    variant="x64v3"
  else
    variant="x64v2"
  fi
  info "CPU 等级: $variant"
  need_cmd apt; need_cmd wget; need_cmd gpg
  wget -qO - https://dl.xanmod.org/archive.key 2>/dev/null \
    | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
  echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' \
    > /etc/apt/sources.list.d/xanmod-release.list
  apt update && apt install -y "linux-xanmod-${variant}" || { err "安装失败"; return 1; }
  enable_bbr
  ok "XanMod 内核安装完成，执行 reboot 重启后生效（BBRv3）"
}

bbr_menu() {
  while :; do
    echo ""
    _cyan "===== 网络优化 ====="
    bbr_status
    echo ""
    echo "  1. 开启 BBR（主线内核可用）"
    echo "  2. 开启 BBRv3（需 XanMod 内核）"
    echo "  0. 返回"
    n=$(read_choice "选择: ")
    case "$n" in
      1) enable_bbr ;;
      2)
        if uname -r | grep -q xanmod; then
          enable_bbr; info "XanMod 内核的 bbr 即为 BBRv3"
        else
          install_xanmod
        fi ;;
      0) return ;;
      *) warn "无效选择" ;;
    esac
  done
}

# ---------- 更新 ----------
update_singbox() {
  local arch ver cur url tmp
  arch=$(detect_arch)
  [ -x "$SB_BIN" ] || { warn "尚未安装，先安装"; install_singbox; return; }
  ver=$(latest_version)
  cur=$("$SB_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  info "当前: v${cur:-未知}  最新: $ver"
  [ "v$cur" = "$ver" ] && { ok "已是最新"; return; }
  url="https://github.com/SagerNet/sing-box/releases/download/${ver}/sing-box-${ver#v}-linux-${arch}.tar.gz"
  tmp=$(mktemp -d)
  curl -L --progress-bar -o "$tmp/sb.tar.gz" "$url" || { err "下载失败"; rm -rf "$tmp"; return 1; }
  tar xzf "$tmp/sb.tar.gz" -C "$tmp"
  cp "$SB_BIN" "$SB_BIN.bak"
  systemctl stop sing-box
  install -m 755 "$tmp/sing-box-${ver#v}-linux-${arch}/sing-box" "$SB_BIN"
  rm -rf "$tmp"
  if sb_check_restart; then
    ok "已更新到 $ver（旧版备份：$SB_BIN.bak）"
  else
    cp "$SB_BIN.bak" "$SB_BIN"; systemctl restart sing-box
    err "新版启动失败，已回滚旧版"
  fi
}

self_update() {
  local remote_ver tmp
  info "检查脚本更新（当前 v$SCRIPT_VER）..."
  tmp=$(mktemp)
  curl -sL --max-time 20 "https://raw.githubusercontent.com/${REPO}/main/sing-box.sh" -o "$tmp" \
    || { err "下载失败，请检查网络或仓库地址"; rm -f "$tmp"; return 1; }
  remote_ver=$(grep '^SCRIPT_VER=' "$tmp" | cut -d'"' -f2)
  if [ -z "$remote_ver" ]; then err "远端脚本异常"; rm -f "$tmp"; return 1; fi
  if [ "$remote_ver" = "$SCRIPT_VER" ]; then ok "已是最新 (v$SCRIPT_VER)"; rm -f "$tmp"; return 0; fi
  info "发现新版 v$remote_ver"
  bash -n "$tmp" || { err "新版脚本语法校验失败，放弃更新"; rm -f "$tmp"; return 1; }
  cp "$tmp" "$0"; chmod +x "$0"; rm -f "$tmp"
  ok "已更新到 v$remote_ver，请重新运行脚本"
}

uninstall_all() {
  local yn
  read -rp "确认卸载 sing-box（含所有节点配置）？(y/n): " yn
  [ "$yn" = "y" ] || return 0
  systemctl stop sing-box sing-box-sub 2>/dev/null || true
  systemctl disable sing-box sing-box-sub 2>/dev/null || true
  rm -f "$SB_SERVICE" "$SB_SUB_SERVICE" "$SB_BIN"
  rm -rf "$SB_DIR"
  systemctl daemon-reload
  ok "已卸载"
}

# ---------- 菜单 ----------
add_node_menu() {
  while :; do
    echo ""
    _cyan "===== 添加节点 ====="
    echo "  1. VLESS + REALITY"
    echo "  2. VLESS + WS + TLS"
    echo "  3. VLESS + WS（明文）"
    echo "  4. TUIC v5"
    echo "  5. Hysteria2"
    echo "  6. AnyTLS"
    echo "  0. 返回"
    input=$(read_choice "选择 (可多选，如 1 4 5，空格分隔): ")
    [ "${input:-}" = "0" ] && return
    # 解析多选，去重，忽略无效项
    local sel nums=()
    for sel in ${input//,/ }; do
      case "$sel" in
        1|2|3|4|5|6)
          [[ " ${nums[*]} " != *" $sel "* ]] && nums+=("$sel") ;;
        *) warn "忽略无效选项: $sel" ;;
      esac
    done
    [ ${#nums[@]} -eq 0 ] && { warn "未选择有效协议"; continue; }
    [ ${#nums[@]} -gt 1 ] && info "将依次添加 ${#nums[@]} 个节点"
    for sel in "${nums[@]}"; do
      case "$sel" in
        1) add_reality ;;
        2) add_ws_tls ;;
        3) add_ws ;;
        4) add_tuic ;;
        5) add_hy2 ;;
        6) add_anytls ;;
      esac
    done
  done
}

sub_menu() {
  while :; do
    echo ""
    _cyan "===== 订阅服务 ====="
    if systemctl is-active -q sing-box-sub 2>/dev/null; then
      echo "状态：运行中"
      sub_urls 2>/dev/null
    else
      echo "状态：未启动"
    fi
    echo ""
    echo "  1. 启动订阅服务"
    echo "  2. 停止订阅服务"
    echo "  3. 重建订阅文件"
    echo "  0. 返回"
    n=$(read_choice "选择: ")
    case "$n" in
      1) sub_server_start ;;
      2) sub_server_stop ;;
      3) build_subscriptions ;;
      0) return ;;
      *) warn "无效选择" ;;
    esac
  done
}

main_menu() {
  while :; do
    echo ""
    _cyan "========== sing-box 一键脚本 v${SCRIPT_VER} =========="
    if [ -x "$SB_BIN" ]; then
      echo "sing-box: $("$SB_BIN" version 2>/dev/null | head -1) ｜ 状态: $(systemctl is-active sing-box 2>/dev/null)"
    else
      echo "sing-box: 未安装"
    fi
    echo "  1. 添加节点"
    echo "  2. 修改节点"
    echo "  3. 删除节点"
    echo "  4. 查看节点"
    echo "  5. 查看订阅"
    echo "  6. 订阅服务管理"
    echo "  7. 证书管理"
    echo "  8. 更新 sing-box 内核"
    echo "  9. 网络优化（BBR / BBRv3）"
    echo " 10. 脚本自更新"
    echo " 11. 卸载"
    echo "  0. 退出"
    n=$(read_choice "选择: ")
    case "$n" in
      1) add_node_menu ;;
      2) modify_node ;;
      3) delete_node ;;
      4) show_nodes ;;
      5) show_subscriptions ;;
      6) sub_menu ;;
      7) cert_menu ;;
      8) update_singbox ;;
      9) bbr_menu ;;
      10) self_update ;;
      11) uninstall_all ;;
      0) exit 0 ;;
      *) warn "无效选择" ;;
    esac
  done
}

# ---------- CLI ----------
usage() {
  cat <<'EOF'
用法:
  sudo bash sing-box.sh                  交互菜单
  sudo bash sing-box.sh --onekey         一键搭建（零交互 REALITY）
  sudo bash sing-box.sh --add-reality [--port 443] [--domain www.microsoft.com]
  sudo bash sing-box.sh --add-tuic [--port 8443]
  sudo bash sing-box.sh --add-hy2 [--port 8443]
  sudo bash sing-box.sh --add-anytls [--port 8443]
  sudo bash sing-box.sh --add-ws [--port 1080]
  sudo bash sing-box.sh --add-ws-tls --domain example.com --cert /path/fullchain --key /path/key [--port 443]
  sudo bash sing-box.sh --show | --update | --self-update | --uninstall
EOF
}

main() {
  check_root
  local port="" domain="" cert="" key=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --port)   port="$2"; shift 2 ;;
      --domain) domain="$2"; shift 2 ;;
      --cert)   cert="$2"; shift 2 ;;
      --key)    key="$2"; shift 2 ;;
      --onekey)
        install_singbox; detect_certs; onekey; exit $? ;;
      --add-reality)
        QUIET=1; install_singbox; detect_certs; add_reality "$port" "$domain"; exit $? ;;
      --add-tuic)
        QUIET=1; install_singbox; detect_certs; add_tuic "$port"; exit $? ;;
      --add-hy2)
        QUIET=1; install_singbox; detect_certs; add_hy2 "$port"; exit $? ;;
      --add-anytls)
        QUIET=1; install_singbox; detect_certs; add_anytls "$port"; exit $? ;;
      --add-ws)
        QUIET=1; install_singbox; detect_certs; add_ws "$port"; exit $? ;;
      --add-ws-tls)
        QUIET=1; install_singbox; detect_certs; add_ws_tls "$port" "$domain" "$cert" "$key"; exit $? ;;
      --show)      show_nodes; exit 0 ;;
      --update)    update_singbox; exit $? ;;
      --self-update) self_update; exit $? ;;
      --uninstall) uninstall_all; exit $? ;;
      -h|--help)   usage; exit 0 ;;
      *) err "未知参数: $1"; usage; exit 1 ;;
    esac
  done
  [ -x "$SB_BIN" ] || install_singbox
  detect_certs
  main_menu
}

main "$@"
