<p align="center"><a href="../i2p.md">Русский</a> · <a href="../en/i2p.md">English</a> · <b>简体中文</b></p>

# 通过 Hydrat 访问 .i2p 网站

I2P 是用于访问 `.i2p` 网站的独立可选服务，不参与普通互联网流量的 VLESS/Tor 路由选择。管理员需要为每个 WireGuard 客户端单独授权，默认关闭。

## 安装

1.2.0 版本提供 amd64 和 arm64 预构建镜像。可选服务使用 `ghcr.io/only-hydrat/hydrat:1.2.0-i2p`。配置好 `.env` 后，在项目根目录执行：

```sh
docker compose -f docker-compose.yml -f docker-compose.i2p.yml pull
docker compose -f docker-compose.yml -f docker-compose.i2p.yml up -d
```

网关、控制器和 I2P 服务应使用相同版本。要使用其他兼容镜像，可在 `.env` 中设置 `HYDRAT_I2P_IMAGE`。后续更新时，请在 Compose 命令中保留 `-f docker-compose.i2p.yml`。

如需开发或从源码构建，添加两个 dev 文件：

```sh
docker compose -f docker-compose.yml -f docker-compose.dev.yml \
  -f docker-compose.i2p.yml -f docker-compose.i2p.dev.yml up -d --build
```

在“客户端”中启用 I2P 访问。“系统 → I2P 网站与地址簿”提供运行状态、手动预热、空闲等待时间和地址管理。首次授权客户端时，Hydrat 会预先启动 I2P。

## 浏览器设置

1. 连接 WireGuard，并保留 Hydrat 配置提供的 DNS。
2. 如果浏览器使用自己的 HTTPS DNS，请为此连接关闭该功能。系统的私人 DNS 也不能绕过网关解析器。
3. 输入完整网址，例如 `http://名称.i2p/`，避免浏览器将地址发送给搜索引擎。普通名称需要地址簿记录；标准公开 `.b32.i2p` 地址不需要。

无需额外的 I2P 应用，也无需设置浏览器代理。此功能支持基于 TCP 的网站，不支持任意 I2P 应用、对外提供服务或 UDP。普通浏览器仍会保留 Cookie 和浏览器指纹。

## 休眠与预热

默认情况下，i2pd 在使用结束后继续运行两小时，然后停止进程。等待时间可设置为 15 分钟至 24 小时。仍然打开的客户端连接会阻止休眠；连接关闭后重新计时。状态检查、普通 VPN 流量和后台地址簿更新不会延长此时间。

休眠期间只保留一个小型管理进程。获准客户端发出的 `.i2p` DNS 请求，或访问此前分配的 IP，都会唤醒 i2pd。已保存的网络信息有助于启动，但隧道需要重新建立。因此不能保证唤醒后立即打开网站；必要时请等待预热完成再刷新页面。“已预热”表示客户端隧道就绪，不代表每个网站都可访问。

## 地址簿

网关首次启动时，Hydrat 会一次性导入[官方 I2P hosts.txt](https://github.com/i2p/i2p.i2p/blob/53002765a300547a2c663ac3c8d50a1b7c56cf1e/installer/resources/hosts.txt)中的 71 个名称。该快照随程序提供，启动时无需连接 GitHub。列表中的论坛地址是 `http://i2pforum.i2p/`，不是 `forum.i2p`。已有记录优先，手动删除的默认记录不会在重启后恢复。地址簿空间不足时，只添加容量允许的记录。名称在列表中并不代表网站当前在线。

- 手动记录接受 `.i2p` 名称以及公开 Destination 或标准 `.b32.i2p` 地址。
- 导入 `hosts.txt` 前可预览错误和冲突。替换已有地址必须确认。
- 导出会保留原始公开 Destination。如果记录只提供 B32，则导出为 `名称=B32`。这是 Hydrat 扩展格式，其他 I2P 客户端可能不支持。
- 订阅支持公网 443 端口的 HTTPS，或 I2P 内的 HTTP(S)。后台更新最多每六小时一次，且仅在 I2P 运行时执行。手动更新可以唤醒 I2P，并在后台完成。
- 新名称会自动加入。已有名称的目标变化进入冲突审核。手动记录优先；删除订阅不会删除已接受的地址。

导入文件和订阅响应上限为 1 MiB，地址簿最多 1024 个名称，订阅最多十个。每个客户端分配新虚拟地址的速率受独立配额限制；配额用尽时，已分配的地址仍可使用。修改 Destination 会分配新虚拟 IP，并关闭旧地址上的连接。旧 IP 永不复用。请随网关数据一起备份地址簿，不要通过删除地址簿来重置设置。

地址和冲突列表分页显示；搜索覆盖整个地址簿。所有订阅保存的冲突共用 1 MiB 的容量上限。超出上限的更新会被拒绝并显示错误，原有数据保持不变。请先处理积累的冲突，再重新更新。

如果 I2P 桥接端口 `19447` 与配置的 Xray 或 Tor 端口重叠，只会禁用 I2P；普通 VPN 服务仍使用原来的端口。网关日志会记录原因。

## 不转发第三方中继流量

i2pd 固定使用 `notransit=true`、`floodfill=false` 和 `share=0`。UPnP、公开管理界面、互联网出口代理以及 I2P 托管服务均关闭。容器不向宿主机发布端口，也不挂载 Docker socket。Hydrat 定期检查中继隧道数量；数量非零或检查失败时会停止 I2P。Tor 仍仅作为客户端，不承担 relay/bridge 工作。

这些设置禁止转发第三方中继流量，但不会隐藏参与 I2P 的事实：相邻节点仍能看到网关 IP。自己的连接仍使用其他网络节点。禁止中继本身并不意味着固定倍数的降速；实际速度取决于隧道、网站、网络状况和容器资源。默认限制为 0.5 CPU 和 384 MiB 内存。

## 隔离与诊断

`.i2p` 请求不会发送到外部 DNS，包括 AAAA、HTTPS 和 SVCB 查询。普通 DNS、onion 和 I2P 使用独立处理队列。I2P 虚拟地址位于 `198.19.0.0/16`，新 onion 地址使用原始范围的下半部分。若已有 onion 映射占用了 I2P 范围，则 I2P 保持不可用，已有 onion 访问继续保留。

```sh
docker compose -f docker-compose.yml -f docker-compose.i2p.yml logs --tail 100 i2pd
docker compose -f docker-compose.yml -f docker-compose.i2p.yml exec i2pd \
  curl --fail --silent --unix-socket /run/hydrat-i2p/control.sock http://localhost/status
```

如果 I2P 因检查失败而停止，请先查看日志。解决原因后，仅重启 `i2pd` 服务。无法检查中继计数时，Hydrat 不会盲目继续运行。

I2P 休眠不会使主服务 `/api/ready` 变为不健康。单个 I2P 网站失败也不会改变客户端的普通路由。检查包括 Go/Node 测试、`scripts/test-onion-integration.sh` 隔离 VPN 测试环境（I2P 桥接使用本地 SOCKS 后端），以及 `scripts/test-i2p-integration.sh`，通过真实 Xray 和 i2pd 进行单独的公网测试。后者会访问公开 I2P 网站，并在测试结束后删除临时容器。本地 SOCKS 测试本身不能证明公网 I2P 可达。

路由器参数：[i2pd 文档](https://docs.i2pd.website/en/latest/user-guide/configuration/)。
