# PS Portal Hop

一个小巧、安全默认、可自建的 HTTP/HTTPS `CONNECT` 正向代理，帮助 PS Portal 从另一个网络出口连接 PlayStation 服务。它可以直接访问目标，也可以链式连接另一个 HTTP 代理。

已在 Windows 局域网环境中通过 PS Portal 实机验证：设备可唤醒并连接 PS5。

> 非 Sony Interactive Entertainment 或 PlayStation 官方项目，与其不存在隶属、赞助或认可关系。PlayStation、PS5 和 PS Portal 是其各自权利人的商标。本项目不是完整的 Remote Play 媒体中继；程序只处理 TCP/HTTP 流量，Remote Play 的 UDP 数据路径是否经过代理，需要用自己的设备实测。

## 为什么叫 Hop

它不是 VPN，也不解密 TLS，更不接管完整的游戏串流。它只是让 Portal 的代理流量多经过一个由你控制的网络出口（hop），重点解决特定网络环境下登录、认证或信令连接不稳定的问题。

## 安全默认值

- 默认只监听 `127.0.0.1:8050`。
- 默认只允许本机客户端。
- 默认阻止访问回环、局域网、链路本地和其他特殊用途目标地址，降低 SSRF 风险。
- `CONNECT` 默认只允许目标端口 `443`，普通 HTTP 默认只允许目标端口 `80`。
- 如果同时配置 `HOST=0.0.0.0` 和 `ALLOWED_CLIENTS=*`，程序默认拒绝启动。只有目标域名受限、端口严格为 `443/80`、私网阻断开启且显式设置 `ALLOW_PUBLIC_RELAY=true` 时，才允许启动公共 Portal 中继。
- 公共中继模式拒绝 IP 形式的目标，并对全局及单客户端的新连接和请求速率设限。

不要把未经限制的正向代理暴露到公网。

## 要求

- Node.js 22 或更高版本
- 可选：Docker 与 Docker Compose

## 第一步：本机自动测试

```powershell
npm install --ignore-scripts
npm test
npm run check
```

测试全部使用本机临时端口，不会访问 Sony 或其他公网服务。

## 第二步：测试电脑本机代理

默认配置只监听本机：

```powershell
npm start
```

另开一个 PowerShell 窗口：

```powershell
curl.exe -x http://127.0.0.1:8050 -I https://www.playstation.com/
```

看到 HTTP 响应表示 HTTPS `CONNECT` 隧道可用。

## 第三步：PS Portal 局域网测试

先确认电脑的局域网网段，例如电脑地址是 `192.168.1.20`，通常可使用 `192.168.1.0/24`：

```powershell
$env:HOST="0.0.0.0"
$env:PORT="8050"
$env:ALLOWED_CLIENTS="127.0.0.1,::1,192.168.1.0/24"
$env:LOG_FORMAT="text"
npm start
```

Windows 防火墙只为专用网络/本地子网开放该端口。需要管理员 PowerShell：

```powershell
New-NetFirewallRule -DisplayName "PS Portal Hop 8050 LAN" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8050 -Profile Private -RemoteAddress LocalSubnet
```

然后在 PS Portal 中手工配置 Wi-Fi 代理：

- 地址：电脑的局域网 IPv4，例如 `192.168.1.20`
- 端口：`8050`

测试完成后可删除防火墙规则：

```powershell
Remove-NetFirewallRule -DisplayName "PS Portal Hop 8050 LAN"
```

观察日志中实际访问的目标域名、连接是否成功，以及代理前后的登录耗时和连接稳定性。日志只记录目标主机和端口，不记录 URL 路径。

## Docker 本地或 VPS 部署

复制示例配置：

```bash
cp .env.example .env
```

至少修改以下配置：

```dotenv
HOST=0.0.0.0
PORT=8050
ALLOWED_CLIENTS=127.0.0.1,::1,你的客户端公网IP/32
```

启动：

```bash
docker compose up -d --build
docker compose logs -f proxy
```

停止：

```bash
docker compose down
```

在 VPS 安全组和系统防火墙中，也应只允许你的客户端公网 IP 访问 TCP 8050。`ALLOWED_CLIENTS` 是第二层保护，不能替代云防火墙。

如果客户端公网 IP 经常变化，不要简单改成 `*`。更安全的方式是让 PS Portal 连接到运行 WireGuard/VPN 客户端的旅行路由器，再由路由器访问 VPS。

如果确实需要让不同公网 IP 的 Portal 直接使用同一台 VPS，可启用受限公共中继：

```dotenv
HOST=0.0.0.0
PORT=8050
ALLOWED_CLIENTS=*
ALLOWED_HOSTS=.playstation.com,.playstation.net,.sony.com,.sonyentertainmentnetwork.com,.google.com,.googleapis.com,.googleapis.cn,.gstatic.com,.googleusercontent.com,.ggpht.com,.googlevideo.com,.android.com,.gvt1.com,.gvt2.com,.gvt3.com,.1e100.net,.withgoogle.com
ALLOWED_CONNECT_PORTS=443
ALLOWED_HTTP_PORTS=80
BLOCK_PRIVATE_TARGETS=true
ALLOW_PUBLIC_RELAY=true
ALLOW_PUBLIC_PROXY=false
```

此模式不是通用开放代理：未列入的域名、IP 形式目标、私网目标及其他端口都会返回 `403`。公网用户仍会消耗你的 VPS 带宽和可选上游代理额度，请保留默认的并发/速率限制并监控日志。

## 配置参考

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | 监听地址；局域网/VPS 使用 `0.0.0.0` |
| `PORT` | `8050` | 监听端口 |
| `ALLOWED_CLIENTS` | `127.0.0.1,::1` | 允许的客户端 IP/CIDR，逗号分隔 |
| `ALLOWED_HOSTS` | `*` | 允许的目标域名；支持精确域名、`.example.com`、`*.example.com` |
| `ALLOWED_CONNECT_PORTS` | `443` | 允许的 CONNECT 目标端口 |
| `ALLOWED_HTTP_PORTS` | `80` | 允许的普通 HTTP 目标端口 |
| `BLOCK_PRIVATE_TARGETS` | `true` | 阻止代理访问私网和特殊用途 IP |
| `ALLOW_PUBLIC_RELAY` | `false` | 允许受目标白名单、端口和私网保护约束的公共中继 |
| `ALLOW_PUBLIC_PROXY` | `false` | 危险逃生开关：允许通用公共代理，不建议启用 |
| `MAX_CONNECTIONS` | `128` | 全局最大客户端连接数 |
| `MAX_CONNECTIONS_PER_CLIENT` | `24` | 单个客户端最大连接数 |
| `MAX_NEW_CONNECTIONS_PER_MINUTE` | `600` | 每分钟允许的新连接总数 |
| `MAX_NEW_CONNECTIONS_PER_CLIENT_PER_MINUTE` | `60` | 单客户端每分钟允许的新连接数 |
| `MAX_REQUESTS_PER_MINUTE` | `1200` | 每分钟允许的 HTTP/CONNECT 请求总数 |
| `MAX_REQUESTS_PER_CLIENT_PER_MINUTE` | `120` | 单客户端每分钟允许的 HTTP/CONNECT 请求数 |
| `UPSTREAM_HOST` | 空 | 可选上游 HTTP 代理地址 |
| `UPSTREAM_PORT` | `8050` | 上游 HTTP 代理端口 |
| `LOG_FORMAT` | `text` | `text`、`json` 或 `silent` |

完整超时和限制配置参见 [.env.example](.env.example)。

## 当前边界

- 不提供 TLS 解密或中间人功能，HTTPS 内容保持端到端加密。
- 不支持 SOCKS、UDP、QUIC 或 TURN。
- 不绕过 PlayStation 账号、区域或订阅限制。
- 域名不是必需项，PS Portal 可以直接填写 VPS 公网 IP 和端口。
- 部署区域是否改善连接取决于客户端运营商、VPS 出口和 Sony 节点，必须实测。

## License

[ISC](LICENSE)
