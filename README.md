# sb-onekey

sing-box 服务端一键脚本。只做 sing-box，不掺 xray。Debian / Ubuntu 通用。

## 快速开始

```bash
curl -L -o sing-box.sh https://raw.githubusercontent.com/asdzx07/sb-onekey/main/sing-box.sh
chmod +x sing-box.sh
sudo bash sing-box.sh              # 交互菜单（运行后自动生成快捷命令 sb，下次直接输入 sb 即可）
sudo bash sing-box.sh --onekey     # 零交互，一键出 REALITY 节点
```

## 功能

| 菜单 | 说明 |
|------|------|
| 添加节点 | 7 种主流协议：VLESS+REALITY、VLESS+WS+TLS、VLESS+WS（明文）、TUIC v5、Hysteria2、AnyTLS、NaiveProxy |
| 修改节点 | 改端口/UUID/密码/备注/域名，改完自动校验+回滚 |
| 删除节点 | 删前备份，校验失败自动回滚 |
| 查看节点 | 入站列表 + 全部客户端链接 |
| 查看订阅 | v2rayN / Clash / sing-box 三种订阅内容 |
| 订阅服务 | 可选的 HTTP 订阅服务（随机端口+token 路径） |
| 证书管理 | 自动检测（acme.sh/certbot/自签）+ 手动添加/删除 |
| 更新内核 | sing-box 内核更新，失败自动回滚旧版 |
| 网络优化 | BBR 一键开；BBRv3 走 XanMod 内核（自动选 x64v2/x64v3，需重启）|
| 脚本自更新 | 从 GitHub 拉新版，语法校验后替换 |
| WebUI 管理 | 优选 IP 订阅生成器 Web 面板（见下） |

## WebUI（优选 IP 订阅生成器）

安装脚本时自动部署，端口 `13530`，主菜单顶部显示地址：

```
WebUI: http://<服务器IP>:13530
```

功能：

- 🖥️ **本机节点**：自动读取本机 sb-onekey 建好的 VLESS+WS(+TLS) 节点，点选即填入表单
- ⚡️ **优选 IP 与远程 txt 挂载**：支持填入优选 IP 列表（`IP:端口#备注`），更**原生支持挂载远程优选 txt / 订阅文件链接（如 `https://.../hk.txt`）**，系统自动定时抓取、Base64 解码并批量提取优选 IP，一键聚合为高可用节点
- 📋 **订阅链接**：`/sub/vless`、`/sub/base64`、`/sub/clash`、`/sub/singbox` 四个直链，改了优选 IP 点保存即生效，不用重新复制；带二维码
- 节点名自动去重（重名的加 `-2`、`-3` 后缀，Clash 不会报 `duplicate name`）

典型用法（美国 VPS 直连慢，套 CF CDN）：

1. sb-onekey 建 VLESS+WS+TLS 节点，域名填套了 CF 的那个
2. 打开 WebUI，点选本机节点，粘贴优选 IP，保存
3. 把 `http://IP:13530/sub/clash` 填到 Clash Verge Rev 里当订阅

## 设计要点

- **REALITY 伪装域名**从内置 域名随机挑（aws.amazon.com、www.microsoft.com、dl.google.com 等）
- **端口防崩溃**：所有添加入口先检查占用（TCP+UDP 双查），被占直接报错退出，配置一行不动；`sing-box check` 校验失败自动回滚
- **双栈**：入站 `listen ::` 原生双栈；v4/v6 可用**不同域名**（也可以回车用 IP），sni 自动跟随各自域名；v4/v6 域名不同时服务端自动配置多证书（SNI 选择）
- **证书**：输入域名自动匹配现成证书；三种兜底：手动填路径、现场自签、粘贴 PEM 内容
- **交互**：v4/v6 链接地址分别询问（域名或 IP）；端口/UUID/密码空回车=随机
- sing-box ≥1.13 原生支持 X25519MLKEM768，无需额外配置

## 命令行模式

```bash
sudo bash sing-box.sh --onekey
sudo bash sing-box.sh --add-reality [--port 443] [--domain www.microsoft.com]
sudo bash sing-box.sh --add-tuic [--port 8443]
sudo bash sing-box.sh --add-hy2 [--port 8443]
sudo bash sing-box.sh --add-anytls [--port 8443]
sudo bash sing-box.sh --add-naive [--port 8443]
sudo bash sing-box.sh --add-ws [--port 1080]
sudo bash sing-box.sh --add-ws-tls --domain example.com \
  --cert /root/.acme.sh/example.com/fullchain.cer \
  --key /root/.acme.sh/example.com/example.com.key [--port 443]
sudo bash sing-box.sh --show | --update | --self-update | --uninstall
```

## 订阅格式

- **v2rayN**：分享链接 base64，v2rayN/v2rayNG/NekoBox 通吃
- **Clash**：Mihomo YAML，proxies + 手动选择代理组
- **sing-box**：outbounds JSON，可直接导入

订阅文件在 `/etc/sing-box/sub/<token>/`，节点增删改自动重建。

## 注意

- 云服务器注意安全组/防火墙放行对应端口（TCP/UDP）
- 订阅服务是 HTTP 明文，含节点凭证，同步完建议关闭
- 未在生产环境实测，建議先用空闲机器验证
