<p align="center">
  <a href="../../README.md">Русский</a> · <a href="../en/README.md">English</a> · <strong>简体中文</strong>
</p>

<p align="center">
  <img src="../../assets/logo.png" alt="Hydrat 标志" width="680" />
</p>
<p align="center">
  <a href="https://golang.org"><img src="https://img.shields.io/github/go-mod/go-version/only-hydrat/hydrat?style=flat-square" alt="Go 版本" /></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="许可证：MIT" /></a>
  <a href="https://github.com/only-hydrat/hydrat/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/only-hydrat/hydrat/ci.yml?branch=main&label=CI&style=flat-square" alt="CI 状态" /></a>
  <a href="../../docker-compose.yml"><img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white&style=flat-square" alt="Docker" /></a>
</p>

<p align="center">
  <strong>基于 WireGuard、Xray 和 Tor 的高可靠智能 VPN 网关</strong><br>
  自动选择最佳 VLESS 与 Tor 代理，在后台验证服务器、隔离故障，并在不中断 WireGuard 隧道的情况下切换路由。
</p>

<p align="center">
  <a href="#现有方案有什么问题">为什么选择 Hydrat？</a> •
  <a href="#主要优势">主要优势</a> •
  <a href="#管理界面">管理界面</a> •
  <a href="#快速开始">快速开始</a> •
  <a href="#架构与工程设计">架构</a> •
  <a href="#运维与监控">运维</a>
</p>

---

## 现有方案有什么问题？

| 方案 | 局限与问题 |
|---|---|
| **原生 WireGuard / OpenVPN** | 运营商可以通过 DPI 快速识别并封锁这些协议。 |
| **Amnezia / Outline** | 绑定到单一固定 IP 或服务器。一旦地址被封锁或主机故障，连接会完全中断，并且需要手动重新配置。 |
| **本地客户端（v2rayN、Happ、Hiddify、sing-box）** | • 持续的后台测速会快速消耗手机电量。<br>• 每台设备都需要安装第三方应用。<br>• 在家用路由器、Apple TV 和智能电视上配置困难，甚至无法配置。<br>• 订阅中可能包含数千条失效或拥塞线路；服务器故障时，用户只能打开应用逐个尝试节点。 |

### Hydrat 的解决方案

**Hydrat 将客户端侧 WireGuard 的简洁性与出口侧 Xray、Tor 的能力结合起来。**

手机、笔记本电脑或家用路由器通过**标准原生 WireGuard**连接到 Hydrat。网关运行在你的 VPS 上，加载包含数千个 VLESS 和 Tor 服务器的订阅，在隔离的后台环境中持续测试它们，并将流量动态路由到最快、最稳定的代理线路。

**核心优势是在不中断 WireGuard 隧道的情况下切换路由。** 当前代理故障时，Hydrat 会让新流量通过网关上的备用路由。若出口或公网 IP 发生变化，已建立的 TCP 或 QUIC 流仍可能需要重新连接。

---

## 主要优势

### 1. 所有设备均使用原生 WireGuard
可使用 iOS、Android、macOS、Windows、Linux 的官方 WireGuard 客户端，也支持 Keenetic、OpenWrt 和 Mikrotik 路由器。无需复杂的第三方代理应用，并能减少手机电量消耗。

### 2. 默认优先使用 VLESS
常规分配会优先为 TCP 选择可用的 VLESS 路由。当主路由是 VLESS 时，备用路由优先选择另一个故障域中的 VLESS；若没有其他安全故障域，也可以使用已预热的 Tor。紧急替换时，会按故障域、负载和评分比较可用且已预热的 VLESS 与 Tor 路由。UDP 始终只使用 VLESS。

### 3. 协调分配 TCP 与 UDP
存在通过 UDP 验证的 VLESS 路由时，调度器会尽量将其同时分配给 TCP 和 UDP。两者仍可能使用不同路由：TCP 可以使用 Tor，UDP 只能使用通过 UDP 验证的 VLESS。

### 4. 自动锦标赛筛选
网关最多可保存来自公开和私有订阅的 10,000 个候选节点。后台流水线通过两个阶段筛选节点：

- **快速探测（Fast Probe）：**快速检查端口和握手是否可用，超时为 6 秒。
- **完整探测（Full Probe）：**验证端到端数据传输及必需的服务关卡，超时为 20 秒。
- 服务器根据延迟、吞吐量和稳定性获得动态 `Score`。连续失败三次的节点会被封禁五小时。

### 5. 故障域隔离
如果订阅中的 50 条配置实际指向同一台服务器或同一个 CDN 前置节点，该服务器故障不应被视为 50 个独立故障。Hydrat 会自动按故障域分组，并确保备用路由来自**另一个独立故障域**。

### 6. 体验质量与可配置服务关卡
主动监控会持续评估真实用户体验：

- 测量真实 TTFB 和下载 64 KiB 样本时的吞吐量。
- 默认检查 YouTube、Instagram、Telegram Web/MTProto、ChatGPT 和 OpenAI API。
- **可配置端点和自定义关卡：**可在 `config.yml` 的 `probes.gate_endpoints` 与 `probes.custom_gates` 中覆盖探测地址，并添加自定义 API 或网站及其允许的 HTTP 状态码。
- 通过 SOCKS5 UDP 验证 QUIC / HTTP/3。
- 通过迟滞机制避免抖动：短暂的延迟波动不会触发切换；替代路由必须确认具有至少 30% 的吞吐量优势。

### 7. 智能直连与地理数据

- **俄罗斯服务直连：**发往 `.ru`、`.su`、`.рф`（`.xn--p1ai`）后缀，以及 `thecode.media`、`habr.com` 和可配置 `direct_domains` 等国际域名下俄罗斯服务的流量会直接转发，避免反滥用系统拒绝境外数据中心 IP 所导致的连接问题。
- **最新 GeoIP 与 GeoSite 数据：**网关支持自动下载并定期更新 [runetfreedom/russia-blocked-geosite](https://github.com/runetfreedom/russia-blocked-geosite) 和 [runetfreedom/russia-blocked-geoip](https://github.com/runetfreedom/russia-blocked-geoip)。俄罗斯资源（`geosite:category-ru`、`geoip:ru`）直连，被封锁的资源（`geosite:russia-blocked`、`geoip:russia-blocked`）则强制通过可用的 VLESS 或 Tor 代理。
- **故障时关闭（Fail-Closed）：**其他不受信任的流量必须通过代理；无可用路由时直接阻断，以防源 IP 泄露。
- **俄罗斯出口保护：**`disallow_ru_egress: true` 会排除位于俄罗斯境内的出口服务器，避免敏感流量经过受当地审查和封锁影响的节点。

---

## 管理界面

管理面板可在 VPN 内通过 `http://10.44.0.1/` 访问。Compose 默认只在主机的 `127.0.0.1:8088` 上发布该端口。如需外部访问，请使用 WireGuard 或带身份验证的 HTTPS 反向代理。不要将面板直接发布为 `0.0.0.0:8088`。

### 1. 仪表盘
展示活跃 VLESS 服务器、可用故障域、就绪 Tor 配置以及筛选流水线状态：

<p align="center">
  <img src="../../assets/dashboard.png" alt="Hydrat 仪表盘" width="900" />
</p>

### 2. 客户端管理
一键创建客户端配置，查看已分配的 TCP/UDP 路由，并为移动设备生成配置文件和二维码：

<p align="center">
  <img src="../../assets/clients.png" alt="WireGuard 客户端管理" width="900" />
</p>

### 3. 来源与订阅
添加 VLESS、Tor、Happ、v2rayN 或 Clash YAML 订阅，预览有效候选节点，并手动或自动刷新：

<p align="center">
  <img src="../../assets/sources.png" alt="来源管理" width="900" />
</p>

### 4. 候选节点锦标赛表
查看服务器测试结果、质量评分、连续成功次数、QoE 状态、TTFB 和吞吐量：

<p align="center">
  <img src="../../assets/candidates.png" alt="候选节点与锦标赛表" width="900" />
</p>

---

## 快速开始

部署流程经过简化，不需要手动执行辅助脚本。

### 系统要求

- Linux 服务器，例如 Ubuntu 22.04 / 24.04 或 Debian 12。
- Docker Engine 和 Docker Compose v2。
- 可访问 `/dev/net/tun`（KVM 和独立服务器通常默认提供）。
- 开放入站端口 `51820/udp`。
- 建议至少 1–2 个 vCPU 和 1 GiB 内存。

### 第 1 步：克隆仓库

```bash
git clone https://github.com/only-hydrat/hydrat.git
cd hydrat
```

### 第 2 步：配置 `.env`

从示例创建 `.env`：

```bash
cp .env.example .env
```

用文本编辑器打开 `.env` 并设置：

```dotenv
# 服务器公网 IP 或域名以及 WireGuard UDP 端口
WIREGUARD_ENDPOINT=203.0.113.10:51820

# 保持为 localhost；外部访问请使用 WireGuard 或 HTTPS 代理
PORTAL_BIND_ADDRESS=127.0.0.1

# 主机上的管理面板端口（默认 8088）
PORTAL_PORT=8088

# 管理面板密码
HYDRAT_ADMIN_PASSWORD=请设置高强度密码
```

> **注意：**如果订阅要求 Happ 硬件密钥验证，请取消注释并设置 `HYDRAT_HWID`。

### 第 3 步：启动 Hydrat

```bash
docker compose up -d --build
```

**完成。** 服务会自动：

- 在 `data/wireguard/wg0.conf` 中生成 WireGuard 服务器私钥，权限为 `0600`。
- 创建 SQLite 和权限为 `0600` 的 `data/controller/secrets/master.key`，用于对敏感载荷字段进行 AES-GCM 保护。这不是完整数据库加密，也不能抵御主机 root 权限访问。
- 应用 nftables 路由规则并启动 Xray 和 Tor。

---

## 两分钟完成连接

1. **打开管理面板：**创建第一个 WireGuard 客户端之前，请从本地计算机建立 SSH 隧道：
   ```bash
   ssh -N -L 8088:127.0.0.1:8088 <user>@<服务器IP>
   ```
   保持 SSH 会话运行，然后访问 `http://127.0.0.1:8088/`。创建客户端后，可通过 WireGuard 访问 `http://10.44.0.1/`，也可以使用 HTTPS 反向代理。浏览器只发送一次密码，Bearer 会话仅保存在内存中；注销或控制器重启都会结束该会话。
2. **添加订阅：**打开**来源**，选择**添加来源**，粘贴 VLESS 或 Tor 订阅 URL，然后选择**导入**。后台验证会立即开始。
3. **创建连接：**打开**客户端**，输入设备名称（例如 `phone`），然后选择**创建**。使用 WireGuard 扫描二维码或下载 `.conf` 文件。
4. **验证连接：**在 WireGuard 中启用隧道。管理面板现在也可通过 `http://10.44.0.1/` 访问。

---

## 架构与工程设计

```text
                           [ WireGuard 客户端 ]
                                      │
                         WireGuard UDP（端口 51820）
                                      ▼
  ┌─────────────────────────── Docker 主机 ─────────────────────────┐
  │                                                                  │
  │  ┌───────────────────────────────┐  ┌──────────────────────────┐ │
  │  │ gateway 容器                  │  │ controller 容器          │ │
  │  │（网络平面，NET_ADMIN）        │  │（隔离的控制平面）        │ │
  │  │                               │  │                          │ │
  │  │ • wg0 接口                    │  │ • SQLite (WAL)           │ │
  │  │ • nftables fwmark 路由        │  │ • 锦标赛引擎             │ │
  │  │ • Main Xray（客户端流量）     │  │ • 调度器与备用路由       │ │
  │  │ • Probe Xray（后台探测）      │  │ • Web 管理面板           │ │
  │  │ • Active Xray（预热备用）     │  │ • REST API               │ │
  │  │ • Tor / Lyrebird（网桥）      │  │                          │ │
  │  └───────────────▲───────────────┘  └────────────▲─────────────┘ │
  │                  │                               │               │
  │                  └───────── Unix 套接字 ─────────┘               │
  │                            (agent.sock)                          │
  └─────────────────────────────────┬────────────────────────────────┘
                                    │
                              动态路由选择
                                    ▼
                       [ VLESS Reality / Tor 代理 ]
```

### 隔离的网关与控制器平面

1. **Gateway：**拥有网络权限（`NET_ADMIN`），负责 WireGuard、nftables、Xray 和 Tor，与用户数据库及加密主密钥隔离。
2. **Controller：**以非特权用户（`UID 10001`）运行在隔离命名空间中，文件系统为 `read_only: true`。它保存 SQLite 并执行评分计算。
3. 两个进程只通过本地 Unix 套接字 `/run/hydrat/agent.sock` 通信。

### 三个 Xray 平面保障连续运行

为避免数千个节点的定期测试影响客户端流量，Xray 进程彼此分离：

- **Main Xray：**仅处理真实客户端流量，不会因探测而重启。
- **Probe Xray：**用于后台候选验证的隔离临时进程；每完成 250 次探测后轮换，以限制内存泄漏。
- **Active Xray：**保持备用服务器连接处于预热状态，以便故障后快速切换。

---

## 运维与监控

### 日志

网关写入结构化日志并自动轮换，`${DATA_DIR:-./data}/logs` 中超过 72 小时的记录会被清理。Gateway 与 controller 使用独立日志目录。读取保留日志需要 root 或 sudo 权限。

查看最后 100 行：

```bash
sudo tail -n 100 "${DATA_DIR:-./data}/logs/gateway/gateway-current.log" \
  "${DATA_DIR:-./data}/logs/controller/controller-current.log"
```

持续查看当前日志：

```bash
sudo tail -F "${DATA_DIR:-./data}/logs/gateway/gateway-current.log" \
  "${DATA_DIR:-./data}/logs/controller/controller-current.log"
```

### 健康状态与就绪状态

- **存活状态：**
  ```bash
  curl -s http://127.0.0.1:8088/api/health
  # {"status":"ok"}
  ```
- **路由与备用容量就绪状态：**
  ```bash
  curl -s http://127.0.0.1:8088/api/ready
  # {"status":"ok"}
  ```

---

## 安全

- **无默认密钥：**仓库不包含预设密钥或密码；首次启动时会生成高强度值。
- **受限权限：**含私钥的配置使用 `0600` 权限。Controller 容器启用 `no-new-privileges: true` 和 `read_only: true`。
- 备份与恢复流程见 [`operations.md`](operations.md)。
- 架构保护与负责任的漏洞披露流程见 [`SECURITY.md`](SECURITY.md)。

---

## 参与贡献

欢迎参与项目。提交更改前请阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md) 和 [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)。

---

## 许可证

本项目采用 MIT 许可证发布。详情见 [`LICENSE`](../../LICENSE)。
