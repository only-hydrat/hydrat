<p align="center"><a href="../onion.md">Русский</a> · <a href="../en/onion.md">English</a> · <b>简体中文</b></p>

# 访问 .onion 网站

在面板的客户端列表中，为所需设备启用“通过 Tor 访问 .onion”。此功能默认关闭，只有管理员可以授权。用户无需以管理员身份登录，即可查看自己的连接状态和使用指南。

“等待应用”表示权限已保存，但网关尚未应用。“路由已就绪”表示 Tor 路由已应用，并不代表某个网站一定在线。“没有就绪的 Tor 路由”表示需要检查 Tor 池。关闭访问后，请等待状态从“正在关闭”变为“已关闭”。

支持公开的 v3 地址、子域名和 TCP。不支持 UDP、v2 地址或要求客户端授权的服务。单个 onion 网站超时不会导致整个 Tor 配置被判定失效。Tor 配置失效时，可切换到另一个就绪配置；已有连接需要重新建立。

## 浏览器设置

控制面板中的指南位于“系统”页面。“我的连接”中的“如何打开 .onion”按钮可直接打开该指南。

### Android：Firefox Nightly

1. 在 Hydrat 中为自己的客户端开启“通过 Tor 访问 .onion”。没有权限时，请联系管理员。启用 WireGuard，并等待状态变为“路由已就绪”。
2. 打开 Mozilla 的 Firefox Nightly。Android 普通版 Firefox 对 `about:config` 的访问有限制。
3. 在地址栏打开 `about:config`，找到 `network.dns.blockDotOnion`，将其设为 `false`。
4. 在 Firefox 设置中找到“DNS over HTTPS”，选择“关闭”，让浏览器使用 VPN 的 DNS。
5. 如果 Android 配置了自定义“私人 DNS”（Private DNS）提供商，请暂时关闭。保留 WireGuard 配置中的 Hydrat DNS，通常为 `10.44.0.1`。
6. 输入带有 `http://` 或 `https://` 前缀的完整 `.onion` 地址，避免浏览器将其发送给搜索引擎。请使用服务官方网站公布的地址。无需设置浏览器代理。
7. 如需恢复设置，将 `network.dns.blockDotOnion` 改回 `true`，并恢复原来的 DNS 设置。也可在 Hydrat 中关闭访问权限。

Android 上的 Chrome、Edge、Brave 及其他浏览器尚无经过确认的 Hydrat 配置方法。使用上述方法时，请打开 Firefox Nightly。

### 其他设备

| 设备和浏览器 | 操作 |
| --- | --- |
| Windows/macOS/Linux 上的 Firefox | 启用 WireGuard 和 Hydrat 访问权限。在 `about:config` 中将 `network.dns.blockDotOnion` 设为 `false`，关闭 DNS over HTTPS，并保留 WireGuard 的 DNS。打开服务官方网站公布的完整 onion 地址。 |
| 电脑上的 Chrome、Edge、Brave 和 Safari | 尚无通用且经过验证的设置；浏览器可能在发起 DNS 请求前就拒绝 onion 地址。通过 Hydrat 访问时，请按上述步骤使用 Firefox。 |
| iPhone/iPad | 暂无经过确认的 Hydrat 直接访问指南。Android 和电脑上的 Firefox 设置不适用于 iOS。普通网站仍可通过 WireGuard 访问。 |

不要关闭 TLS 证书验证。这些说明依据浏览器文档编写；尚未逐一测试所有真实设备与浏览器的组合。

## 路由与隐私

网关只为获授权的客户端在本地解析 `.onion`，并从 `198.18.0.0/15` 分配持久虚拟 IPv4 地址。这些 DNS 查询，包括 AAAA 和 HTTPS/SVCB，均不会发送到外部解析器。普通域名仍由原来的 dnsmasq 处理，其内部监听地址为 `127.0.0.1:1053`。

网关通过私有 Unix 控制套接字和 cookie 身份验证，使用 `MAPADDRESS` 向正在服务的 Tor 配置写入映射。映射恢复完成后，才发布 onion 就绪状态；探索配置转为服务配置时，也会重新恢复映射。每个客户端使用独立 SOCKS 身份；原有 TCP/UDP 分配不变。虚拟地址规则优先于 GeoRules 和直连规则。未授权或没有可用路由时，此地址段被阻断。无需开放公网 SOCKS 或控制端口。

此功能提供便利访问，并不替代 Tor Browser 的隐私保护。普通浏览器仍保留指纹和 cookies。网关管理员可以读取本地映射文件中的 onion 域名。该文件未加密，权限为 `0600`；本模块不会在 DNS 日志中记录域名。

## 持久化状态

`onion-mappings.json`、`.initialized` 标记和 `.lock` 文件与 `applied-plan.json` 位于同一目录。请随网关及 WireGuard 状态一起备份映射文件和标记。**`hydrat backup` 只备份 SQLite，不包含这些文件。** 为获得一致备份，请先停止 gateway，再复制其状态目录。只要客户端可能缓存更新的地址，就不能删除映射文件或恢复较旧的副本。

同一地址不会分配给另一个域名，表中最多保存 1024 个域名。容量耗尽、文件损坏或丢失时，新的 onion 访问将被阻断，普通 DNS 仍可工作。请恢复最新状态，不要删除标记来绕过保护。WireGuard 子网不得与 `198.18.0.0/15` 重叠。

参考：、[Firefox DNS](https://support.mozilla.org/kb/firefox-dns-over-https)、[Firefox 首选项](https://searchfox.org/firefox-main/source/modules/libpref/init/StaticPrefList.yaml)、、[MAPADDRESS](https://spec.torproject.org/control-spec/commands.html#mapaddress)。

新域名分配有速率限制：每个客户端允许突发 8 次，每 6 秒补充一次额度；共享额度允许突发 16 次，每秒补充一次。已分配的域名不消耗额度。慢速 Tor 查询不会占用普通 DNS 的并发额度。

开发者可以在装有 Docker 和 Go 的 Linux 开发机上运行 `scripts/test-onion-integration.sh`。脚本下载固定版本的 Tor Chutney，构建测试镜像，并在无外部网络的容器中建立本地 Tor 网络和两个 WireGuard 客户端。测试需要 privileged 容器；请勿在生产主机运行。结束后自动清理容器和临时数据。

普通 DNS 查询通过 UDP 发送给 dnsmasq；收到截断响应时，再通过 TCP 重试。onion 主用和备用配置通过附加检查队列接受主动检查，不占用为普通主用和备用路由预留的队列。

## Tor 质量检查

启用 onion 访问后，现有 QoE 监测机制会通过实际承载流量的 Tor 配置，检查 DuckDuckGo 和 Tor Project 的官方 onion 网站。检查共用现有并发限制，不从 VPS 直接发送 HTTP 请求，也不单独下载文件测量 onion 吞吐量。Onion 检查结果不会改变普通 TCP/UDP 路由的质量评分。

只有在另一条独立网桥近期成功访问同一服务时，请求失败才会计入该配置的故障。如果两条路径都失败，结果仍为不确定。多次确认的失败或持续缓慢的响应会通过现有 QoE 采样窗口降低评分。检查期间 Tor 进程被替换时，该结果会被丢弃。

健康的主配置保持不变，以免中断已有连接。备用配置根据近期检查结果选择；主配置质量确认下降时，也可以切换到第三个已就绪的配置。其余已通过资格检查的网桥会在现有的有限 Tor 进程池中依次接受检查，不会同时启动所有网桥。首次访问任意 onion 网站时，仍可能需要等待建立线路。所有客户端关闭 onion 访问后，这些检查随即停止。
