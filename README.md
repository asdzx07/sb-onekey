# sb-onekey

sing-box 服务端一键脚本。只做 sing-box，不掺 xray。Debian / Ubuntu 通用。

## 快速开始

```bash
curl -L -o sing-box.sh https://raw.githubusercontent.com/asdzx07/sb-onekey/main/sing-box.sh
chmod +x sing-box.sh
sudo bash sing-box.sh              # 交互菜单
sudo bash sing-box.sh --onekey     # 零交互，一键出 REALITY 节点
```

## 功能

| 菜单 | 说明 |
|------|------|
| 添加节点 | 6 种主流协议：VLESS+REALITY、VLESS+WS+TLS、VLESS+WS（明文）、TUIC v5、Hysteria2、AnyTLS |
| 修改节点 | 改端口/UUID/密码/备注/域名，改完自动校验+回滚 |
| 删除节点 | 删前备份，校验失败自动回滚 |
| 查看节点 | 入站列表 + 全部客户端链接 |
| 查看订阅 | v2rayN / Clash / sing-box 三种订阅内容 |
| 订阅服务 | 可选的 HTTP 订阅服务（随机端口+token 路径） |
| 证书管理 | 自动检测（acme.sh/certbot/自签）+ 手动添加/删除 |
| 更新内核 | sing-box 内核更新，失败自动回滚旧版 |
| 网络优化 | BBR 一键开；BBRv3 走 XanMod 内核（自动选 x64v2/x64v3，需重启）|
| 脚本自更新 | 从 GitHub 拉新版，语法校验后替换 |

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
