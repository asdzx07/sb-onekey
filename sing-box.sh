#!/bin/bash
# sing-box 一键脚本 v2 (server 端)
# 6 种主流协议 / 交互+一键双模式 / 证书自动检测 / 订阅三件套
# 用法: sudo bash sing-box.sh              (交互菜单)
#       sudo bash sing-box.sh --onekey     (零交互一键搭建 REALITY)
#       sudo bash sing-box.sh --add-reality [--port 443] [--domain www.microsoft.com]
#       sudo bash sing-box.sh --add-tuic | --add-hy2 | --add-anytls | --add-ws | --add-ws-tls
#       sudo bash sing-box.sh --show | --update | --self-update | --uninstall

SCRIPT_VER="2.3.0"
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
  err "随机端口 20 次都没挑到空闲的，手动指定吧" >&2
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
  # $1: 用途描述。回车=随机。注意：内部提示必须走 stderr，避免被 $() 捕获
  local input p
  while :; do
    read -rp "端口 [回车=随机]: " input
    if [ -z "$input" ]; then
      p=$(random_port) || continue
      info "随机端口: $p" >&2
      echo "$p"; return 0
    fi
    if ! [[ "$input" =~ ^[0-9]+$ ]] || [ "$input" -lt 1 ] || [ "$input" -gt 65535 ]; then
      warn "端口不合法" >&2; continue
    fi
    if port_in_use "$input"; then warn "端口 $input 已被占用" >&2; continue; fi
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

# ---------- 证书自动检测 ----------
declare -A CERT_MAP  # 域名 -> "cert|key"
declare -A CERT_SRC  # 域名 -> 来源说明

cert_valid_for() {
  local cert="$1" domain="$2"
  openssl x509 -checkend 0 -noout -in "$cert" 2>/dev/null || return 1
  cert_covers_domain "$cert" "$domain" && return 0
  return 1
}

# 证书覆盖的所有 DNS 域名（SAN，去掉通配符的 *），每行一个
cert_all_domains() {
  openssl x509 -noout -in "$1" -ext subjectAltName 2>/dev/null \
    | grep -o "DNS:[^,]*" | cut -d: -f2 | sed 's/^\*\.//' | sort -u
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
  # 用户手动放证书的常见目录：/root/cert/<域名>/fullchain.pem + privkey.pem
  # SAN 证书会按其覆盖的所有域名分别注册
  for d in /root/cert/*/; do
    [ -d "$d" ] || continue
    c="${d}fullchain.pem"; k="${d}privkey.pem"
    [ -f "$c" ] && [ -f "$k" ] || continue
    openssl x509 -checkend 0 -noout -in "$c" 2>/dev/null || continue
    for domain in $(cert_all_domains "$c"); do
      [ -n "${CERT_MAP[$domain]:-}" ] && continue
      CERT_MAP["$domain"]="$c|$k"; CERT_SRC["$domain"]="/root/cert 自动检测"
    done
  done
  for f in "$SB_CERTS"/*.crt; do
    [ -f "$f" ] || continue
    base=$(basename "$f" .crt); k="$SB_CERTS/${base}.key"
    # 已有正式证书的不被自签覆盖
    [ -n "${CERT_MAP[$base]:-}" ] && continue
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

# 展示已检测证书，供用户挑选
show_detected_certs() {
  if [ ${#CERT_MAP[@]} -gt 0 ]; then
    echo "本机检测到以下证书："
    local d
    for d in "${!CERT_MAP[@]}"; do
      echo "  - $d（${CERT_SRC[$d]:-未知来源}，有效期至 $(cert_expiry "${CERT_MAP[$d]%%|*}")）"
    done
  else
    warn "本机未检测到可用证书"
  fi
}

# $1: 域名 → stdout 输出 "cert_path key_path"
resolve_cert() {
  local domain="$1" entry c k yn choice line
  mkdir -p "$SB_CERTS"
  entry="${CERT_MAP[$domain]:-}"
  # 域名没命中但本机有证书时，让用户从列表里挑
  if [ -z "$entry" ] && [ ${#CERT_MAP[@]} -gt 0 ]; then
    echo "[$domain] 没有匹配的证书，本机有以下证书：" >&2
    local d i=1 pick
    local clist=()
    for d in "${!CERT_MAP[@]}"; do
      echo "  $((i++)). $d" >&2
      clist+=("$d")
    done
    read -rp "输入序号使用其中一个，回车继续其他方式: " pick
    pick=$(echo "$pick" | tr -d '\r' | xargs)
    if [[ "$pick" =~ ^[0-9]+$ ]] && [ "$pick" -ge 1 ] && [ "$pick" -le ${#clist[@]} ]; then
      domain="${clist[$((pick-1))]}"
      entry="${CERT_MAP[$domain]}"
      echo "已切换域名为: $domain" >&2
    fi
  fi
  if [ -n "$entry" ]; then
    c="${entry%%|*}"; k="${entry##*|}"
    echo "检测到 [$domain] 的现成证书 (${CERT_SRC[$domain]:-})：" >&2
    echo "  证书: $c" >&2
    echo "  私钥: $k" >&2
    read -rp "回车直接使用，n 换其他方式 [Y/n]: " yn
    if [ "${yn:-Y}" != "n" ] && [ "${yn:-Y}" != "N" ]; then
      echo "$c $k $domain"; return 0
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
      echo "$c $k $domain"; return 0 ;;
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
      echo "$c $k $domain"; return 0 ;;
    *)
      need_cmd openssl
      c="$SB_CERTS/${domain}.crt"; k="$SB_CERTS/${domain}.key"
      openssl req -x509 -newkey rsa:2048 -keyout "$k" -out "$c" -days 3650 -nodes \
        -subj "/CN=${domain}" >/dev/null 2>&1
      chmod 600 "$c" "$k"
      echo "$c $k $domain"; return 0 ;;
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
  install_webui
}

# ---------- WebUI（优选 IP 订阅生成器） ----------
WEBUI_DIR="/opt/pref-sub"
WEBUI_PORT="13530"
install_webui() {
  # 从脚本自带 webui/ 目录安装（仓库合并后自带，无需再 clone）
  local src_dir
  src_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)/webui"
  [ -d "$src_dir" ] || { warn "未找到 webui 目录，跳过 WebUI 安装"; return 0; }
  mkdir -p "$WEBUI_DIR"
  cp -f "$src_dir/index.html" "$src_dir/server.py" "$WEBUI_DIR/"
  cat > /etc/systemd/system/pref-sub.service <<EOF
[Unit]
Description=Pref-Sub Web UI
After=network.target
[Service]
Type=simple
WorkingDirectory=$WEBUI_DIR
ExecStart=/usr/bin/python3 $WEBUI_DIR/server.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable pref-sub >/dev/null 2>&1
  systemctl restart pref-sub >/dev/null 2>&1
  ok "WebUI 已安装: $(webui_url)"
}
webui_url() {
  local ip
  ip=$(get_public_ip 0 2>/dev/null)
  echo "http://${ip:-<本机IP>}:$WEBUI_PORT"
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
  # 按创建时间排序（老的在前），方便用户按添加顺序找节点
  local f tag created
  for f in "$SB_NODES"/*.json; do
    [ -f "$f" ] || continue
    tag=$(basename "$f" .json)
    created=$(python3 -c "import json;print(json.load(open('$f')).get('created',''))" 2>/dev/null)
    printf '%s\t%s\n' "$created" "$tag"
  done | sort | cut -f2
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
  iss=$(openssl x509 -noout -in "$1" -issuer 2>/dev/null | sed 's/^issuer= *//')
  sub=$(openssl x509 -noout -in "$1" -subject 2>/dev/null | sed 's/^subject= *//')
  [ -n "$iss" ] && [ "$iss" = "$sub" ]
}

# 判断是否为域名（非 IP）。是域名返回0
is_domain() {
  local s="$1"
  [[ "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && return 1
  [[ "$s" =~ ^\[.*\]$ ]] && return 1
  [[ "$s" == *:* ]] && return 1
  [ -n "$s" ] && return 0
  return 1
}

# 询问 v4/v6 链接地址 → 设置 LINK_V4 / LINK_V6（域名或IP，空=不用）
# 上次用过的域名会自动记住，回车直接复用
ask_link_addrs() {
  local h4 h6 d4 d6 last4 last6
  h4=$(get_public_ip 0 2>/dev/null)
  h6=$(get_public_ip6 2>/dev/null)
  last4=$(cat "$SB_DIR/last-v4-domain" 2>/dev/null)
  last6=$(cat "$SB_DIR/last-v6-domain" 2>/dev/null)
  read -rp "IPv4 链接地址 [输入域名，ip=用IP${h4:+ $h4}，回车=${last4:+$last4}${last4:-用IP${h4:+ $h4}}]: " d4
  d4=$(echo "$d4" | tr -d '\r' | xargs)
  if [ -n "$d4" ]; then
    if [ "$d4" = "ip" ]; then LINK_V4="${h4:-}"
    else LINK_V4="$d4"; echo "$d4" > "$SB_DIR/last-v4-domain"; fi
  elif [ -n "$last4" ]; then LINK_V4="$last4"
  elif [ -n "$h4" ]; then LINK_V4="$h4"
  else LINK_V4=""; fi

  read -rp "IPv6 链接地址 [输入域名，n=不生成v6节点，回车=${last6:+$last6}${last6:-用IP${h6:+ [$h6]}}]: " d6
  d6=$(echo "$d6" | tr -d '\r' | xargs)
  if [ "$d6" = "n" ] || [ "$d6" = "N" ]; then LINK_V6=""
  elif [ -n "$d6" ]; then LINK_V6="$d6"; echo "$d6" > "$SB_DIR/last-v6-domain"
  elif [ -n "$last6" ]; then LINK_V6="$last6"
  elif [ -n "$h6" ]; then LINK_V6="[$h6]"
  else LINK_V6=""; fi

  if [ -z "$LINK_V4" ] && [ -z "$LINK_V6" ]; then
    err "至少需要一个链接地址"; return 1
  fi
}

# QUIET 模式的链接地址（IP，双栈）
quiet_link_addrs() {
  local h4 h6
  h4=$(get_public_ip 1 2>/dev/null)
  h6=$(get_public_ip6 2>/dev/null)
  LINK_V4="${h4:-}"; LINK_V6=""
  [ -n "$h6" ] && LINK_V6="[$h6]"
  [ -z "$LINK_V4" ] && [ -z "$LINK_V6" ] && { err "无法获取公网地址"; return 1; }
}

# 证书是否覆盖某域名（SAN / 通配符 / CN）
# $1: 证书路径 $2: 域名 → 0=覆盖
cert_covers_domain() {
  local cert="$1" domain="$2" san parent
  san=$(openssl x509 -noout -in "$cert" -ext subjectAltName 2>/dev/null)
  echo "$san" | grep -q "DNS:${domain}" && return 0
  parent="${domain#*.}"
  [ "$parent" != "$domain" ] && echo "$san" | grep -q "DNS:\*.${parent}" && return 0
  openssl x509 -noout -in "$cert" -subject 2>/dev/null | grep -qE "CN *= *${domain}([, /]|$)" && return 0
  return 1
}

# 为 LINK_V4/LINK_V6 解析证书（单入站只支持一张证书）
# → 填充 CERT_DOMAINS/CERT_PATHS/CERT_KEYS/CERT_SELF（单元素数组）
# 注意：sing-box 的 certificate/key 数组是「单张 PEM 的分行」，不是多证书！
# 传多张 PEM 会被 join 成一张，SNI 选择根本不会生效。v2.1.0 的多证书设计是错的。
resolve_link_certs() {
  CERT_DOMAINS=(); CERT_PATHS=(); CERT_KEYS=(); CERT_SELF=()
  local d c k primary=""
  for d in "$LINK_V4" "$LINK_V6"; do
    [ -z "$d" ] && continue
    is_domain "$d" || continue
    [ -z "$primary" ] && primary="$d"
  done
  if [ -z "$primary" ]; then fallback_cert_domain; return $?; fi
  info "解析证书（单入站只支持一张证书）..."
  read -r c k primary <<< "$(resolve_cert "$primary")" || return 1
  CERT_DOMAINS=("$primary"); CERT_PATHS=("$c"); CERT_KEYS=("$k")
  if is_self_signed "$c"; then CERT_SELF=(1); else CERT_SELF=(0); fi
  # 证书覆盖校验：不覆盖的链接域名，SNI 回退到证书域名
  for d in "$LINK_V4" "$LINK_V6"; do
    [ -z "$d" ] && continue
    is_domain "$d" || continue
    if ! cert_covers_domain "$c" "$d"; then
      warn "证书 [$primary] 不覆盖 [$d]，该链接 SNI 将使用 [$primary]"
      warn "如需 SNI 与链接域名一致，请申请一张同时覆盖两个域名的证书"
    fi
  done
  SNI_V4=$(sni_for "$LINK_V4"); SNI_V6=$(sni_for "$LINK_V6")
  return 0
}

# 无域名时的兜底：问一个证书域名（默认 bing.com 自签）
fallback_cert_domain() {
  local domain c k
  show_detected_certs
  domain=$(ask_domain "bing.com")
  read -r c k domain <<< "$(resolve_cert "$domain")" || return 1
  CERT_DOMAINS=("$domain"); CERT_PATHS=("$c"); CERT_KEYS=("$k")
  if is_self_signed "$c"; then CERT_SELF=(1); else CERT_SELF=(0); fi
  SNI_V4=$(sni_for "$LINK_V4"); SNI_V6=$(sni_for "$LINK_V6")
}

# 生成 tls 的证书部分 JSON → TLS_CERT_JSON
# $1: 额外字段（如 '"alpn":["h3"],'）
# 只用单证书（certificate_path/key_path）。不要传多张 PEM，sing-box 会 join 成一张。
build_tls_cert_json() {
  local extra="${1:-}"
  [ ${#CERT_DOMAINS[@]} -eq 0 ] && { err "没有可用证书"; return 1; }
  TLS_CERT_JSON="\"certificate_path\":\"${CERT_PATHS[0]}\",\"key_path\":\"${CERT_KEYS[0]}\""
  TLS_CERT_JSON="\"enabled\":true,\"server_name\":\"${CERT_DOMAINS[0]}\",${extra}${TLS_CERT_JSON}"
}

# 链接的 sni：证书覆盖链接域名则用链接域名，否则用证书域名（单证书无 SNI 选择）
# $1: link host
sni_for() {
  if is_domain "$1" && [ ${#CERT_PATHS[@]} -gt 0 ] && cert_covers_domain "${CERT_PATHS[0]}" "$1"; then
    echo "$1"
  else
    echo "${CERT_DOMAINS[0]:-bing.com}"
  fi
}

# 链接的 insecure 参数：$1: link host $2: 参数名（allow_insecure/insecure）
insecure_for() {
  local h="$1" param="$2" d i
  d=$(sni_for "$h")
  for ((i=0; i<${#CERT_DOMAINS[@]}; i++)); do
    if [ "${CERT_DOMAINS[i]}" = "$d" ] && [ "${CERT_SELF[i]}" = "1" ]; then
      echo "&${param}=1"; return 0
    fi
  done
  echo ""
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
  local uuid keypair priv pub shortid tag links=()
  info "添加 VLESS + REALITY"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && { port=443; port_in_use "$port" && port=$(random_port); }
    ensure_port_free "$port" || return 1
    [ -z "$domain" ] && domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
    uuid=$("$SB_BIN" generate uuid)
    quiet_link_addrs || return 1
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "REALITY"); fi
    if [ -z "$domain" ]; then
      domain=${REALITY_DOMAINS[$((RANDOM % ${#REALITY_DOMAINS[@]}))]}
      info "随机伪装域名: $domain (如需指定下次用 --domain)"
    fi
    uuid=$(ask_uuid)
    ask_link_addrs || return 1
  fi
  keypair=$("$SB_BIN" generate reality-keypair)
  priv=$(echo "$keypair" | grep -i private | awk '{print $NF}')
  pub=$(echo "$keypair" | grep -i public | awk '{print $NF}')
  shortid=$(openssl rand -hex 8)
  tag="reality-${port}"

  PENDING_INBOUND=$(cat <<EOF
{"type":"vless","tag":"$tag","listen":"::","listen_port":$port,
 "users":[{"uuid":"$uuid","flow":"xtls-rprx-vision"}],
 "tls":{"enabled":true,"server_name":"$domain",
  "reality":{"enabled":true,"handshake":{"server":"$domain","server_port":443},
   "private_key":"$priv","short_id":["$shortid"]}}}
EOF
)
  local base="vless://${uuid}@%s:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${domain}&fp=chrome&pbk=${pub}&sid=${shortid}&type=tcp"
  [ -n "$LINK_V4" ] && links+=("$(printf "$base#REALITY-${port}" "$LINK_V4")")
  [ -n "$LINK_V6" ] && links+=("$(printf "$base#REALITY-${port}-v6" "$LINK_V6")")
  local meta hosts_json
  hosts_json=$(python3 -c "import json;print(json.dumps([x for x in ['$LINK_V4','$LINK_V6'] if x]))")
  meta=$(cat <<EOF
{"tag":"$tag","proto":"vless-reality","name":"REALITY-${port}","port":$port,
 "uuid":"$uuid","password":null,"domain":"$domain","path":null,
 "pubkey":"$pub","shortid":"$shortid","cert":null,"key":null,"selfsigned":false,
 "link_v4":"$LINK_V4","link_v6":"$LINK_V6","sni_v4":"$SNI_V4","sni_v6":"$SNI_V6","hosts":$hosts_json,
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "VLESS+REALITY" "${links[@]}"
}

# ---------- 2. VLESS + WS + TLS ----------
# ---------- 2. VLESS + WS + TLS ----------
add_ws_tls() {
  local port="${1:-}" domain="${2:-}" cert="${3:-}" key="${4:-}"
  local uuid path tag links=()
  info "添加 VLESS + WS + TLS"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && { port=443; port_in_use "$port" && port=$(random_port); }
    ensure_port_free "$port" || return 1
    [ -z "$domain" ] && { err "CLI 模式需要 --domain"; return 1; }
    [ -z "$cert" ] || [ -z "$key" ] && { err "CLI 模式需要 --cert 和 --key"; return 1; }
    uuid=$("$SB_BIN" generate uuid)
    quiet_link_addrs || return 1
    CERT_DOMAINS=("$domain"); CERT_PATHS=("$cert"); CERT_KEYS=("$key")
    if is_self_signed "$cert"; then CERT_SELF=(1); else CERT_SELF=(0); fi
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "VLESS/WS/TLS"); fi
    if [ -n "$domain" ] && [ -n "$cert" ]; then
      CERT_DOMAINS=("$domain"); CERT_PATHS=("$cert"); CERT_KEYS=("$key")
      if is_self_signed "$cert"; then CERT_SELF=(1); else CERT_SELF=(0); fi
    else
      show_detected_certs
      ask_link_addrs || return 1
      resolve_link_certs || return 1
      if [ ${#CERT_DOMAINS[@]} -eq 0 ]; then
        fallback_cert_domain || return 1
      fi
    fi
    uuid=$(ask_uuid)
  fi
  # CLI 指定了 domain 但没走 ask_link_addrs 时补上
  [ -z "${LINK_V4:-}" ] && [ -z "${LINK_V6:-}" ] && { quiet_link_addrs || return 1; }
  path="/$(openssl rand -hex 6)"
  tag="ws-tls-${port}"
  build_tls_cert_json || return 1

  PENDING_INBOUND="{\"type\":\"vless\",\"tag\":\"$tag\",\"listen\":\"::\",\"listen_port\":$port,"
  PENDING_INBOUND+="\"users\":[{\"uuid\":\"$uuid\"}],"
  PENDING_INBOUND+="\"transport\":{\"type\":\"ws\",\"path\":\"$path\"},"
  PENDING_INBOUND+="\"tls\":{$TLS_CERT_JSON}}"

  local enc_path="$path"
  local h sni ins suffix base
  for h in "$LINK_V4" "$LINK_V6"; do
    [ -z "$h" ] && continue
    sni=$(sni_for "$h")
    ins=$(insecure_for "$h" "insecure")
    suffix=""; { [ "$h" = "$LINK_V6" ] && [ -n "$LINK_V4" ]; } && suffix="-v6"
    base="vless://${uuid}@%s:${port}?encryption=none&security=tls&sni=${sni}&type=ws&path=${enc_path}&host=${sni}${ins}"
    links+=("$(printf "$base#WS-TLS-${port}${suffix}" "$h")")
  done

  local meta hosts_json
  build_certs_json
  hosts_json=$(python3 -c "import json;print(json.dumps([x for x in ['$LINK_V4','$LINK_V6'] if x]))")
  meta=$(cat <<EOF
{"tag":"$tag","proto":"vless-ws-tls","name":"WS-TLS-${port}","port":$port,
 "uuid":"$uuid","password":null,"domain":"${CERT_DOMAINS[0]}","path":"$path",
 "pubkey":null,"shortid":null,"certs":$CERTS_JSON,"selfsigned":$META_SELFSIGNED,
 "link_v4":"$LINK_V4","link_v6":"$LINK_V6","sni_v4":"$SNI_V4","sni_v6":"$SNI_V6","hosts":$hosts_json,
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "VLESS+WS+TLS" "${links[@]}"
}


# ---------- 3. VLESS + WS (明文) ----------
add_ws() {
  local port="${1:-}"
  local uuid path tag links=()
  info "添加 VLESS + WS (明文无 TLS，一般配合 CDN/反代使用)"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && port=$(random_port)
    ensure_port_free "$port" || return 1
    uuid=$("$SB_BIN" generate uuid)
    quiet_link_addrs || return 1
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "VLESS/WS"); fi
    uuid=$(ask_uuid)
    ask_link_addrs || return 1
  fi
  path="/$(openssl rand -hex 6)"
  tag="ws-${port}"

  PENDING_INBOUND=$(cat <<EOF
{"type":"vless","tag":"$tag","listen":"::","listen_port":$port,
 "users":[{"uuid":"$uuid"}],
 "transport":{"type":"ws","path":"$path"}}
EOF
)
  local enc_path="$path"
  local base="vless://${uuid}@%s:${port}?encryption=none&type=ws&path=${enc_path}&security=none"
  [ -n "$LINK_V4" ] && links+=("$(printf "$base#WS-${port}" "$LINK_V4")")
  [ -n "$LINK_V6" ] && links+=("$(printf "$base#WS-${port}-v6" "$LINK_V6")")
  local meta hosts_json
  hosts_json=$(python3 -c "import json;print(json.dumps([x for x in ['$LINK_V4','$LINK_V6'] if x]))")
  meta=$(cat <<EOF
{"tag":"$tag","proto":"vless-ws","name":"WS-${port}","port":$port,
 "uuid":"$uuid","password":null,"domain":null,"path":"$path",
 "pubkey":null,"shortid":null,"cert":null,"key":null,"selfsigned":false,
 "link_v4":"$LINK_V4","link_v6":"$LINK_V6","sni_v4":"$SNI_V4","sni_v6":"$SNI_V6","hosts":$hosts_json,
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "VLESS+WS" "${links[@]}"
}

# ---------- 4. TUIC v5 ----------
# ---------- 4. TUIC v5 ----------
add_tuic() {
  local port="${1:-}"
  local uuid passwd tag links=()
  info "添加 TUIC v5"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && port=$(random_port)
    ensure_port_free "$port" || return 1
    uuid=$("$SB_BIN" generate uuid); passwd=$(openssl rand -hex 12)
    quiet_link_addrs || return 1
    CERT_DOMAINS=("bing.com")
    local c="$SB_CERTS/tuic-${port}.crt" k="$SB_CERTS/tuic-${port}.key"
    mkdir -p "$SB_CERTS"
    openssl req -x509 -newkey rsa:2048 -keyout "$k" -out "$c" -days 3650 -nodes \
      -subj "/CN=bing.com" >/dev/null 2>&1
    chmod 600 "$c" "$k"
    CERT_PATHS=("$c"); CERT_KEYS=("$k"); CERT_SELF=(1)
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "TUIC"); fi
    show_detected_certs
    ask_link_addrs || return 1
    resolve_link_certs || return 1
    if [ ${#CERT_DOMAINS[@]} -eq 0 ]; then
      fallback_cert_domain || return 1
    fi
    uuid=$(ask_uuid); passwd=$(ask_password)
  fi
  tag="tuic-${port}"
  build_tls_cert_json '"alpn":["h3"],' || return 1

  PENDING_INBOUND="{\"type\":\"tuic\",\"tag\":\"$tag\",\"listen\":\"::\",\"listen_port\":$port,"
  PENDING_INBOUND+="\"users\":[{\"uuid\":\"$uuid\",\"password\":\"$passwd\"}],"
  PENDING_INBOUND+="\"congestion_control\":\"bbr\","
  PENDING_INBOUND+="\"tls\":{$TLS_CERT_JSON}}"

  local h sni ins suffix
  for h in "$LINK_V4" "$LINK_V6"; do
    [ -z "$h" ] && continue
    sni=$(sni_for "$h")
    ins=$(insecure_for "$h" "allow_insecure")
    suffix=""; { [ "$h" = "$LINK_V6" ] && [ -n "$LINK_V4" ]; } && suffix="-v6"
    links+=("tuic://${uuid}:${passwd}@${h}:${port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=${sni}${ins}#TUIC-${port}${suffix}")
  done

  local meta hosts_json
  build_certs_json
  hosts_json=$(python3 -c "import json;print(json.dumps([x for x in ['$LINK_V4','$LINK_V6'] if x]))")
  meta=$(cat <<EOF
{"tag":"$tag","proto":"tuic","name":"TUIC-${port}","port":$port,
 "uuid":"$uuid","password":"$passwd","domain":"${CERT_DOMAINS[0]}","path":null,
 "pubkey":null,"shortid":null,"certs":$CERTS_JSON,"selfsigned":$META_SELFSIGNED,
 "link_v4":"$LINK_V4","link_v6":"$LINK_V6","sni_v4":"$SNI_V4","sni_v6":"$SNI_V6","hosts":$hosts_json,
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "TUIC" "${links[@]}"
}


# ---------- 5. Hysteria2 ----------
# ---------- 5. Hysteria2 ----------
add_hy2() {
  local port="${1:-}"
  local passwd tag links=()
  info "添加 Hysteria2"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && port=$(random_port)
    ensure_port_free "$port" || return 1
    passwd=$(openssl rand -hex 16)
    quiet_link_addrs || return 1
    CERT_DOMAINS=("bing.com")
    local c="$SB_CERTS/hy2-${port}.crt" k="$SB_CERTS/hy2-${port}.key"
    mkdir -p "$SB_CERTS"
    openssl req -x509 -newkey rsa:2048 -keyout "$k" -out "$c" -days 3650 -nodes \
      -subj "/CN=bing.com" >/dev/null 2>&1
    chmod 600 "$c" "$k"
    CERT_PATHS=("$c"); CERT_KEYS=("$k"); CERT_SELF=(1)
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "Hysteria2"); fi
    show_detected_certs
    ask_link_addrs || return 1
    resolve_link_certs || return 1
    if [ ${#CERT_DOMAINS[@]} -eq 0 ]; then
      fallback_cert_domain || return 1
    fi
    passwd=$(ask_password)
  fi
  tag="hy2-${port}"
  build_tls_cert_json '"alpn":["h3"],' || return 1

  PENDING_INBOUND="{\"type\":\"hysteria2\",\"tag\":\"$tag\",\"listen\":\"::\",\"listen_port\":$port,"
  PENDING_INBOUND+="\"users\":[{\"password\":\"$passwd\"}],"
  PENDING_INBOUND+="\"tls\":{$TLS_CERT_JSON}}"

  local h sni ins suffix
  for h in "$LINK_V4" "$LINK_V6"; do
    [ -z "$h" ] && continue
    sni=$(sni_for "$h")
    ins=$(insecure_for "$h" "insecure")
    suffix=""; { [ "$h" = "$LINK_V6" ] && [ -n "$LINK_V4" ]; } && suffix="-v6"
    links+=("hysteria2://${passwd}@${h}:${port}?sni=${sni}${ins}#HY2-${port}${suffix}")
  done

  local meta hosts_json
  build_certs_json
  hosts_json=$(python3 -c "import json;print(json.dumps([x for x in ['$LINK_V4','$LINK_V6'] if x]))")
  meta=$(cat <<EOF
{"tag":"$tag","proto":"hy2","name":"HY2-${port}","port":$port,
 "uuid":null,"password":"$passwd","domain":"${CERT_DOMAINS[0]}","path":null,
 "pubkey":null,"shortid":null,"certs":$CERTS_JSON,"selfsigned":$META_SELFSIGNED,
 "link_v4":"$LINK_V4","link_v6":"$LINK_V6","sni_v4":"$SNI_V4","sni_v6":"$SNI_V6","hosts":$hosts_json,
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "Hysteria2" "${links[@]}"
}


# ---------- 6. AnyTLS ----------
# ---------- 6. AnyTLS ----------
add_anytls() {
  local port="${1:-}"
  local passwd tag links=()
  info "添加 AnyTLS"
  if [ "$QUIET" = "1" ]; then
    [ -z "$port" ] && port=$(random_port)
    ensure_port_free "$port" || return 1
    passwd=$(openssl rand -hex 16)
    quiet_link_addrs || return 1
    CERT_DOMAINS=("bing.com")
    local c="$SB_CERTS/anytls-${port}.crt" k="$SB_CERTS/anytls-${port}.key"
    mkdir -p "$SB_CERTS"
    openssl req -x509 -newkey rsa:2048 -keyout "$k" -out "$c" -days 3650 -nodes \
      -subj "/CN=bing.com" >/dev/null 2>&1
    chmod 600 "$c" "$k"
    CERT_PATHS=("$c"); CERT_KEYS=("$k"); CERT_SELF=(1)
  else
    if [ -n "$port" ]; then ensure_port_free "$port" || return 1
    else port=$(ask_port "AnyTLS"); fi
    show_detected_certs
    ask_link_addrs || return 1
    resolve_link_certs || return 1
    if [ ${#CERT_DOMAINS[@]} -eq 0 ]; then
      fallback_cert_domain || return 1
    fi
    passwd=$(ask_password)
  fi
  tag="anytls-${port}"
  build_tls_cert_json || return 1

  PENDING_INBOUND="{\"type\":\"anytls\",\"tag\":\"$tag\",\"listen\":\"::\",\"listen_port\":$port,"
  PENDING_INBOUND+="\"users\":[{\"password\":\"$passwd\"}],"
  PENDING_INBOUND+="\"tls\":{$TLS_CERT_JSON}}"

  local h sni ins suffix
  for h in "$LINK_V4" "$LINK_V6"; do
    [ -z "$h" ] && continue
    sni=$(sni_for "$h")
    ins=$(insecure_for "$h" "insecure")
    suffix=""; { [ "$h" = "$LINK_V6" ] && [ -n "$LINK_V4" ]; } && suffix="-v6"
    links+=("anytls://${passwd}@${h}:${port}?sni=${sni}${ins}#AnyTLS-${port}${suffix}")
  done

  local meta hosts_json
  build_certs_json
  hosts_json=$(python3 -c "import json;print(json.dumps([x for x in ['$LINK_V4','$LINK_V6'] if x]))")
  meta=$(cat <<EOF
{"tag":"$tag","proto":"anytls","name":"AnyTLS-${port}","port":$port,
 "uuid":null,"password":"$passwd","domain":"${CERT_DOMAINS[0]}","path":null,
 "pubkey":null,"shortid":null,"certs":$CERTS_JSON,"selfsigned":$META_SELFSIGNED,
 "link_v4":"$LINK_V4","link_v6":"$LINK_V6","sni_v4":"$SNI_V4","sni_v6":"$SNI_V6","hosts":$hosts_json,
 "created":"$(date '+%F %T')"}
EOF
)
  finish_add "$tag" "$meta" "AnyTLS" "${links[@]}"
}

# 生成 certs 数组 JSON → CERTS_JSON；设置 META_SELFSIGNED
build_certs_json() {
  CERTS_JSON=$(python3 -c "
import json
doms = '''${CERT_DOMAINS[*]}'''.split()
paths = '''${CERT_PATHS[*]}'''.split()
keys = '''${CERT_KEYS[*]}'''.split()
selfs = '''${CERT_SELF[*]}'''.split()
print(json.dumps([{'domain': d, 'cert': c, 'key': k, 'selfsigned': bool(int(s))}
                  for d, c, k, s in zip(doms, paths, keys, selfs)]))")
  if [[ " ${CERT_SELF[*]} " == *" 1 "* ]]; then META_SELFSIGNED=true; else META_SELFSIGNED=false; fi
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
  # 原子写入：先写临时目录，成功后才 mv 覆盖，避免失败时留下坏订阅
  local tmpdir
  tmpdir=$(mktemp -d)
  # 超时保护：Python 超过 60 秒未完成则杀掉，防止 hung 死进程
  SB_NODES="$SB_NODES" SUBDIR="$tmpdir" timeout 60 python3 - <<'PYEOF'
import json, os, glob, base64

nodes = []
for f in sorted(glob.glob(os.path.join(os.environ["SB_NODES"], "*.json"))):
    try:
        nodes.append(json.load(open(f)))
    except Exception:
        pass
subdir = os.environ["SUBDIR"]

def cert_ss(n, sni):
    # 按 SNI 域名找对应的证书状态；找不到则回退到节点级 selfsigned
    for c in n.get("certs") or []:
        if c.get("domain") == sni:
            return bool(c.get("selfsigned"))
    return bool(n.get("selfsigned"))

def is_dom(h):
    import re
    if not h: return False
    if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', h): return False
    if h.startswith("["): return False
    if ":" in h: return False
    return True

def bare_host(h):
    return h[1:-1] if h.startswith("[") else h

def sni_of(h, default):
    return h if is_dom(h) else default

def link_hosts(n):
    # 返回 [(host, sni)] 列表；优先用创建时按证书覆盖算好的 sni_v4/sni_v6
    out = []
    default_sni = n.get("domain") or "bing.com"
    for key, skey in (("link_v4", "sni_v4"), ("link_v6", "sni_v6")):
        h = n.get(key)
        if h:
            out.append((h, n.get(skey) or sni_of(h, default_sni)))
    if not out:
        for h in n.get("hosts", []):
            out.append((h, sni_of(h, default_sni)))
    return out

def gen_links(n):
    # 优先用创建时存好的链接
    if n.get("links"):
        return n["links"]
    links = []
    for h, sni in link_hosts(n):
        port, name = n["port"], n["name"]
        p = n["proto"]
        if p == "vless-reality":
            links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp=chrome&pbk={n['pubkey']}&sid={n['shortid']}&type=tcp#{name}")
        elif p == "vless-ws-tls":
            path = n["path"]
            links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&security=tls&sni={sni}&type=ws&path={path}&host={sni}#{name}")
        elif p == "vless-ws":
            path = n["path"]
            links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&type=ws&path={path}&security=none#{name}")
        elif p == "tuic":
            ins = "&allow_insecure=1" if cert_ss(n, sni) else ""
            links.append(f"tuic://{n['uuid']}:{n['password']}@{h}:{port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni={sni}{ins}#{name}")
        elif p == "hy2":
            ins = "&insecure=1" if cert_ss(n, sni) else ""
            links.append(f"hysteria2://{n['password']}@{h}:{port}?sni={sni}{ins}#{name}")
        elif p == "anytls":
            ins = "&insecure=1" if cert_ss(n, sni) else ""
            links.append(f"anytls://{n['password']}@{h}:{port}?sni={sni}{ins}#{name}")
    return links

# 1) v2rayN：分享链接 base64
all_links = []
for n in nodes:
    all_links.extend(gen_links(n))
with open(os.path.join(subdir, "v2rayn"), "w") as f:
    f.write(base64.b64encode("\n".join(all_links).encode()).decode())

# 2) clash.yaml
L = []
L.append("proxies:")
proxy_names = []
for n in nodes:
    port, name, p = n["port"], n["name"], n["proto"]
    for h_raw, sni in link_hosts(n):
        skip = "true" if cert_ss(n, sni) else "false"
        h = bare_host(h_raw)
        pname = name if h_raw == (n.get("link_v4") or "") else name + "-v6"
        if not n.get("link_v4") or not n.get("link_v6"):
            pname = name
        proxy_names.append(pname)
        if p == "vless-reality":
            L.append(f"""- name: "{pname}"
  type: vless
  server: {h}
  port: {port}
  uuid: {n['uuid']}
  udp: true
  tls: true
  network: tcp
  flow: xtls-rprx-vision
  servername: {sni}
  client-fingerprint: chrome
  reality-opts:
    public-key: {n['pubkey']}
    short-id: {n['shortid']}
    support-x25519mlkem768: true""")
        elif p in ("vless-ws-tls", "vless-ws"):
            tls = "true" if p == "vless-ws-tls" else "false"
            sn = f"\n  servername: {sni}" if p == "vless-ws-tls" else ""
            host_h = f"\n      Host: {sni}" if p == "vless-ws-tls" else ""
            L.append(f"""- name: "{pname}"
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
            L.append(f"""- name: "{pname}"
  type: tuic
  server: {h}
  port: {port}
  uuid: {n['uuid']}
  password: {n['password']}
  alpn: [h3]
  sni: {sni}
  skip-cert-verify: {skip}
  congestion-controller: bbr
  udp-relay-mode: native""")
        elif p == "hy2":
            L.append(f"""- name: "{pname}"
  type: hysteria2
  server: {h}
  port: {port}
  password: {n['password']}
  sni: {sni}
  skip-cert-verify: {skip}""")
        elif p == "anytls":
            L.append(f"""- name: "{pname}"
  type: anytls
  server: {h}
  port: {port}
  password: {n['password']}
  client-fingerprint: chrome
  sni: {sni}
  skip-cert-verify: {skip}""")
L.append("")
L.append("proxy-groups:")
L.append("  - name: 手动选择")
L.append("    type: select")
L.append("    proxies:")
for pn in proxy_names:
    L.append(f'      - "{pn}"')
with open(os.path.join(subdir, "clash.yaml"), "w") as f:
    f.write("\n".join(L) + "\n")

# 3) singbox.json — 完整客户端配置（可直接导入 sing-box 客户端）
outbounds = []
node_tags = []
for n in nodes:
    port, p = n["port"], n["proto"]
    for h_raw, sni in link_hosts(n):
        h = bare_host(h_raw)
        tag = n["name"] if h_raw == (n.get("link_v4") or "") else n["name"] + "-v6"
        if not n.get("link_v4") or not n.get("link_v6"):
            tag = n["name"]
        node_tags.append(tag)
        if p == "vless-reality":
            outbounds.append({"type": "vless", "tag": tag, "server": h, "server_port": port,
                "uuid": n["uuid"], "flow": "xtls-rprx-vision",
                "tls": {"enabled": True, "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": n["pubkey"], "short_id": n["shortid"]}}})
        elif p == "vless-ws-tls":
            outbounds.append({"type": "vless", "tag": tag, "server": h, "server_port": port,
                "uuid": n["uuid"],
                "transport": {"type": "ws", "path": n["path"], "headers": {"Host": sni}},
                "tls": {"enabled": True, "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "insecure": cert_ss(n, sni)}})
        elif p == "vless-ws":
            outbounds.append({"type": "vless", "tag": tag, "server": h, "server_port": port,
                "uuid": n["uuid"], "transport": {"type": "ws", "path": n["path"]}})
        elif p == "tuic":
            outbounds.append({"type": "tuic", "tag": tag, "server": h, "server_port": port,
                "uuid": n["uuid"], "password": n["password"],
                "congestion_control": "bbr", "udp_relay_mode": "native",
                "tls": {"enabled": True, "server_name": sni, "alpn": ["h3"],
                    "insecure": cert_ss(n, sni)}})
        elif p == "hy2":
            outbounds.append({"type": "hysteria2", "tag": tag, "server": h, "server_port": port,
                "password": n["password"],
                "tls": {"enabled": True, "server_name": sni, "alpn": ["h3"],
                    "insecure": cert_ss(n, sni)}})
        elif p == "anytls":
            outbounds.append({"type": "anytls", "tag": tag, "server": h, "server_port": port,
                "password": n["password"],
                "tls": {"enabled": True, "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "insecure": cert_ss(n, sni)}})
outbounds.append({"type": "selector", "tag": "手动选择", "outbounds": node_tags,
                  "default": node_tags[0] if node_tags else "direct"})
outbounds.append({"type": "direct", "tag": "direct"})
outbounds.append({"type": "block", "tag": "block"})
outbounds.append({"type": "dns", "tag": "dns-out"})
sb_config = {
    "log": {"level": "info", "timestamp": True},
    "dns": {
        "servers": [
            {"tag": "google", "type": "tls", "server": "8.8.8.8"},
            {"tag": "local", "type": "udp", "server": "223.5.5.5", "detour": "direct"}
        ],
        "rules": [{"outbound": "any", "server": "local"}],
        "final": "google"
    },
    "inbounds": [
        {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
         "listen_port": 1080, "sniff": True}
    ],
    "outbounds": outbounds,
    "route": {
        "rules": [
            {"protocol": "dns", "outbound": "dns-out"},
            {"ip_cidr": ["224.0.0.0/3", "ff00::/8"], "outbound": "block"}
        ],
        "final": "手动选择",
        "auto_detect_interface": True
    }
}
with open(os.path.join(subdir, "singbox.json"), "w") as f:
    json.dump(sb_config, f, indent=2, ensure_ascii=False)
print(f"订阅已生成：{len(nodes)} 个节点")
PYEOF
  local py_rc=$?
  if [ $py_rc -eq 0 ] && [ -f "$tmpdir/v2rayn" ] && [ -f "$tmpdir/clash.yaml" ] && [ -f "$tmpdir/singbox.json" ]; then
    # 备份旧订阅，失败时可回滚
    local bakdir="$subdir.bak.$(date +%Y%m%d%H%M%S)"
    [ -f "$subdir/v2rayn" ] && mkdir -p "$bakdir" && cp "$subdir"/v2rayn "$subdir"/clash.yaml "$subdir"/singbox.json "$bakdir/" 2>/dev/null
    mv "$tmpdir"/v2rayn "$tmpdir"/clash.yaml "$tmpdir"/singbox.json "$subdir/"
    # 只保留最近 3 个备份
    ls -dt "$SB_SUB"/.*.bak.* "$subdir".bak.* 2>/dev/null | tail -n +4 | xargs -r rm -rf
    echo "订阅已更新：$subdir"
  else
    warn "订阅生成失败（Python 退出码 $py_rc），已保留旧订阅，临时文件已清理"
  fi
  rm -rf "$tmpdir"
  return $py_rc
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
  # 选择节点 → 输出 tag（列表走 stderr，避免被 $() 捕获）
  local tags i=1 t n
  mapfile -t tags < <(list_node_tags)
  [ ${#tags[@]} -eq 0 ] && { warn "还没有节点"; return 1; }
  for t in "${tags[@]}"; do
    n=$(python3 -c "import json;print(json.load(open('$SB_NODES/$t.json')).get('name',''))" 2>/dev/null)
    echo "  $((i++)). $t ($n)" >&2
  done
  n=$(read_choice "选择 (序号): ")
  t=${tags[$((n-1))]:-}
  [ -z "$t" ] && { warn "无效序号" >&2; return 1; }
  echo "$t"
}

pick_nodes() {
  # 多选节点 → 每行输出一个 tag（支持 "1 3 5"、"1,3,5"、"all"）
  local tags i=1 t n input sel
  mapfile -t tags < <(list_node_tags)
  [ ${#tags[@]} -eq 0 ] && { warn "还没有节点" >&2; return 1; }
  for t in "${tags[@]}"; do
    n=$(python3 -c "import json;print(json.load(open('$SB_NODES/$t.json')).get('name',''))" 2>/dev/null)
    echo "  $((i++)). $t ($n)" >&2
  done
  input=$(read_choice "选择 (可多选，如 1 3 / 1,3，all=全部): ")
  local nums=()
  if [ "$input" = "all" ]; then
    for ((i=0; i<${#tags[@]}; i++)); do nums+=("$((i+1))"); done
  else
    for sel in ${input//,/ }; do
      case "$sel" in
        ''|*[!0-9]*) warn "忽略无效选项: $sel" >&2 ;;
        *)
          if [ "$sel" -ge 1 ] && [ "$sel" -le "${#tags[@]}" ]; then
            [[ " ${nums[*]} " != *" $sel "* ]] && nums+=("$sel")
          else
            warn "忽略无效序号: $sel" >&2
          fi ;;
      esac
    done
  fi
  [ ${#nums[@]} -eq 0 ] && { warn "未选择有效节点" >&2; return 1; }
  for sel in "${nums[@]}"; do
    echo "${tags[$((sel-1))]}"
  done
}

regen_node_links() {
  # $1: tag → 根据元数据重新生成 links 并写回（sni 跟随各自链接域名）
  SB_NODES="$SB_NODES" RETAG="$1" python3 - <<'PYEOF2'
import json, os, re
p = os.path.join(os.environ["SB_NODES"], os.environ["RETAG"] + ".json")
n = json.load(open(p))

def is_dom(h):
    if not h: return False
    if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', h): return False
    if h.startswith("["): return False
    if ":" in h: return False
    return True

def sni_of(h, default):
    return h if is_dom(h) else default

def cert_ss(n, sni):
    for c in n.get("certs") or []:
        if c.get("domain") == sni:
            return bool(c.get("selfsigned"))
    return bool(n.get("selfsigned"))

links = []
hosts = []
for key, skey in (("link_v4", "sni_v4"), ("link_v6", "sni_v6")):
    h = n.get(key)
    if h: hosts.append((h, n.get(skey)))
if not hosts:
    hosts = [(h, None) for h in n.get("hosts", [])]
default_sni = n.get("domain") or "bing.com"
port, name, q = n["port"], n["name"], n["proto"]
for h, sni_stored in hosts:
    sni = sni_stored or sni_of(h, default_sni)
    suffix = "-v6" if h == n.get("link_v6") and n.get("link_v4") else ""
    if q == "vless-reality":
        links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp=chrome&pbk={n['pubkey']}&sid={n['shortid']}&type=tcp#{name}{suffix}")
    elif q == "vless-ws-tls":
        path = n["path"]
        links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&security=tls&sni={sni}&type=ws&path={path}&host={sni}#{name}{suffix}")
    elif q == "vless-ws":
        path = n["path"]
        links.append(f"vless://{n['uuid']}@{h}:{port}?encryption=none&type=ws&path={path}&security=none#{name}{suffix}")
    elif q == "tuic":
        ins = "&allow_insecure=1" if cert_ss(n, sni) else ""
        links.append(f"tuic://{n['uuid']}:{n['password']}@{h}:{port}?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni={sni}{ins}#{name}{suffix}")
    elif q == "hy2":
        ins = "&insecure=1" if cert_ss(n, sni) else ""
        links.append(f"hysteria2://{n['password']}@{h}:{port}?sni={sni}{ins}#{name}{suffix}")
    elif q == "anytls":
        ins = "&insecure=1" if cert_ss(n, sni) else ""
        links.append(f"anytls://{n['password']}@{h}:{port}?sni={sni}{ins}#{name}{suffix}")
n["links"] = links
n["hosts"] = hosts
json.dump(n, open(p, "w"), indent=2, ensure_ascii=False)
print("\n".join(links))
PYEOF2
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
  echo "  5) 链接地址（v4/v6 域名）"
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
      echo "修改链接地址（v4/v6 可用不同域名）"
      ask_link_addrs || return 1
      update_node_field "$tag" "link_v4" "$LINK_V4"
      update_node_field "$tag" "link_v6" "$LINK_V6"
      if [ "$proto" = "vless-reality" ]; then
        : # REALITY 无需证书，sni 仍是伪装域名
      elif [[ "$proto" == "tuic" || "$proto" == "hy2" || "$proto" == "anytls" || "$proto" == "vless-ws-tls" ]]; then
        resolve_link_certs || { cp "$SB_CONF.bak" "$SB_CONF"; err "已回滚"; return 1; }
        if [ ${#CERT_DOMAINS[@]} -eq 0 ]; then
          fallback_cert_domain || { cp "$SB_CONF.bak" "$SB_CONF"; err "已回滚"; return 1; }
        fi
        local extra=""
        { [ "$proto" = "tuic" ] || [ "$proto" = "hy2" ]; } && extra='"alpn":["h3"],'
        build_tls_cert_json "$extra"
        SB_CONF="$SB_CONF" UPTAG="$tag" NEW_TLS="$TLS_CERT_JSON" python3 - <<'PYEOF3'
import json, os
pp = os.environ["SB_CONF"]
conf = json.load(open(pp))
tls_json = "{" + os.environ["NEW_TLS"] + "}"
for i in conf.get("inbounds", []):
    if i.get("tag") == os.environ["UPTAG"]:
        i["tls"] = json.loads(tls_json)
json.dump(conf, open(pp, "w"), indent=2, ensure_ascii=False)
PYEOF3
        build_certs_json
        SB_NODES="$SB_NODES" UFTAG="$tag" UDOMAIN="${CERT_DOMAINS[0]}" UCERTS="$CERTS_JSON" USELF="$META_SELFSIGNED" python3 - <<'PYEOF4'
import json, os
pp = os.path.join(os.environ["SB_NODES"], os.environ["UFTAG"] + ".json")
nn = json.load(open(pp))
nn["domain"] = os.environ["UDOMAIN"]
nn["certs"] = json.loads(os.environ["UCERTS"])
nn["selfsigned"] = os.environ["USELF"] == "true"
json.dump(nn, open(pp, "w"), indent=2, ensure_ascii=False)
PYEOF4
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
  local tags tag yn
  mapfile -t tags < <(pick_nodes) || return 1
  echo "将删除以下 ${#tags[@]} 个节点：" >&2
  for tag in "${tags[@]}"; do echo "  - $tag" >&2; done
  read -rp "确认删除？(y/n): " yn
  [ "$yn" = "y" ] || return 0
  cp "$SB_CONF" "$SB_CONF.bak"
  for tag in "${tags[@]}"; do
    json_del_inbound "$tag"
    del_node_meta "$tag"
  done
  if sb_check_restart; then
    build_subscriptions 2>/dev/null || true
    ok "已删除 ${#tags[@]} 个节点: ${tags[*]}"
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
      echo "WebUI: $(webui_url) ｜ 状态: $(systemctl is-active pref-sub 2>/dev/null)"
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
    echo " 12. WebUI 管理（优选 IP 订阅）"
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
      12) webui_menu ;;
      0) exit 0 ;;
      *) warn "无效选择" ;;
    esac
  done
}

webui_menu() {
  while :; do
    echo ""
    _cyan "===== WebUI 管理（优选 IP 订阅生成器）====="
    echo "地址: $(webui_url)"
    echo "状态: $(systemctl is-active pref-sub 2>/dev/null)"
    echo "  1. 重装/更新 WebUI"
    echo "  2. 重启 WebUI"
    echo "  3. 查看状态"
    echo "  0. 返回"
    n=$(read_choice "选择: ")
    case "$n" in
      1) install_webui ;;
      2) systemctl restart pref-sub; ok "已重启: $(webui_url)" ;;
      3) systemctl status pref-sub --no-pager | head -12 ;;
      0) return ;;
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

# 被 source 时只定义函数，不跑主流程（防 hung 死进程）
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
