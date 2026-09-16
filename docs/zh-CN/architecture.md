<p align="center">
  <a href="../architecture.md">Русский</a> · <a href="../en/architecture.md">English</a> · <strong>简体中文</strong>
</p>

# Hydrat 架构

Hydrat 由两个运行在不同网络命名空间中的 Go 进程组成。

- `hydrat agent` 管理 WireGuard、nftables、main/probe Xray、Tor 配置以及所有依赖网络的探测。
- `hydrat controller` 管理来源、自适应锦标赛、调度器、SQLite 和管理界面。

两个进程通过 Unix 套接字上的 HTTP/JSON 通信。管理面板可在 WireGuard 内通过 `http://10.44.0.1:80` 访问：gateway 使用 nftables 将 8080 端口重定向到 80，并用内部令牌签署真实的 WireGuard IP；controller 不信任伪造的代理头。Compose 在主机上只以 `${PORTAL_BIND_ADDRESS:-127.0.0.1}:${PORTAL_PORT:-8088}:8080` 发布面板。外部访问应使用 WireGuard 或带身份验证的 HTTPS 反向代理，不要直接绑定 `0.0.0.0:8088`。

客户端 DNS 与外部 DNS 上游彼此分离。`wireguard.dns` 将 `10.44.0.1` 写入新客户端配置，`xray.dns_resolvers` 定义公共地址池（`1.1.1.1`、`9.9.9.9`、`8.8.8.8`）；单值 `xray.dns_resolver` 仅为兼容性保留。Gateway 命名空间中的独立受监管 dnsmasq 提供该地址：它并行请求独立上游、缓存响应、快速重试丢失的请求，并可在短暂上游故障时返回旧缓存。DNS 不经过客户端已分配的有状态 Xray handler，因此不会随单个 VLESS/XHTTP 会话一起冻结。代价是 DNS 从 gateway 容器直接出站，与客户端选择的 TCP/Tor 路由无关。拦截和配置仅存在于 gateway 命名空间内的 nftables/dnsmasq，不会修改主机或其他容器的 DNS。上游地址不得指回 WireGuard gateway。

每条 TCP 路由的 QoE 检查仍会通过该路由的独立 SOCKS 代理，向确定选择的上游发送 DNS-over-TCP。发生错误时，直连控制请求会并行检查整个地址池：至少一个上游可达即可证明是路由的用户侧退化；整个池都故障时不会降低单条路由评分。

该命名空间中的透明策略路由使用 Hydrat 专属优先级 `10000`。如果相同优先级存在不兼容的外部规则，bootstrap 会停止，但不会删除或修改该规则。

Agent 会持久化已应用计划。重启后，它等待 Xray 就绪，对保存的 generation 执行 add → route，之后才进入 ready。因此重启 gateway 不需要重启 controller，重启 controller 也不会撤销已应用路由。

TCP 与 UDP 分配彼此独立。存在通过 UDP 验证的 VLESS 时，调度器会尽量同时用于 TCP 与 UDP。TCP 可以使用 VLESS 或已预热的单网桥 Tor 配置；UDP 只能使用已验证的 VLESS。紧急替换时，Tor 与 VLESS 一同参与 TCP 候选池，并按故障域、负载和评分成为替代路由；常规主路由仍优先 VLESS。

识别出的 `.ru`、`.su`、`.xn--p1ai` 域名以及 `direct_domains` 中的地址会直连。启用 `routing.geo_rules.enabled: true` 后，GeoRules 使用定期更新的 GeoSite 和 GeoIP 数据库（默认每 24 小时更新 `russia-blocked-geosite` 与 `russia-blocked-geoip`）：`geosite:category-ru` 和 `geoip:ru` 走 `direct`，`geosite:russia-blocked` 与 `geoip:russia-blocked` 强制代理。`routing.disallow_ru_egress: true` 会在预探测阶段排除俄罗斯境内的出口节点；状态保存到配置和 `routing.json`。未知流量继续走代理，无合格路由时故障关闭。当前不支持 IPv6、NaiveProxy、onion 路由和 core 自动更新。

来源通过管理面板维护。混合输入预览接受 VLESS 链接、VLESS 订阅 URL、Tor 网桥行和网桥列表 URL。`obfs4` 与 `webtunnel` 可以省略可选的 `Bridge` 前缀；解析器以 `Bridge <原始行>` 的规范形式保存。未知传输、无效地址和指纹仍会判定为无效。

敏感载荷字段在写入 SQLite 前使用 AES-GCM 加密。这不是完整 SQLite 加密，也不能抵御主机 root 权限泄露。刷新期间现有路由继续工作，刷新失败时保留最后一次确认有效的候选清单。

内部 `source_position` 从零开始。版本 3 迁移按 `created_at, id` 为现有候选建立后备顺序；成功刷新会在事务中用当前订阅顺序替换它。Controller 按存储顺序读取，不按指纹重新排序 Tor 候选。Tor 队列优先级会考虑 inventory generation：当前未探测候选先于重试，同一优先级用 `source_position` 排序。被并发刷新删除的旧候选会被跳过而不中断循环；下一轮使用新清单，并把新出现的候选排在重试之前。

## 因果观测状态

Fast、full 和 active 探测各自拥有独立的持久化时钟。网络 RPC 前，controller 预留对应阶段的序号：`*_result_seq` 是已分配时钟，`*_applied_seq` 是最后原子应用的结果。预留 N+1 不会取消正在运行的 N。只要结果序号大于 applied 时钟就会被接受，因此 N 后接 N+1 可以依次应用，但 N+1 已应用后迟到的 N 会被拒绝。拒绝不会改变健康状态、探测状态、样本、事件或故障域证据。Qualification 在发送 RPC 前通过单个事务预留所选批次。

Full probe 启动时还会保存 `failure_generation`。Full 或 active 的 hard failure 应用后会递增 generation，因此更早开始的 full 结果不能恢复该路由。Active success 检查同一 generation，不能覆盖较新的 hard failure。普通 active 结果只更改可用性和恢复状态；评分及服务关卡属于 full qualification。Active hard failure 会原子更改可用性、探测状态、failure generation，并为 VLESS 更新故障域证据。基础设施故障不会创建 hard-failure 证据，也不会递增 generation。

## 候选生命周期

候选遵循持久化生命周期 `active → draining → retired → delete`。成功刷新会将缺失条目设为 `draining`，保留加密载荷，并设置 `drain_after`（默认 15 分钟）。同一稳定 ID 在删除前重新出现会回到 `active`。Qualification 和新分配只使用 active 清单；现有 assignment/plan 在 controller 安全替换期间仍可暂时读取并观测 draining 路由。

维护收集器每轮最多处理 32 个到期候选。只有 desired/applied generation 相等、assignments、working pool 和两个持久化计划均无引用、`inventory_epoch` 未变化且 Tor reconcile 已确认时，才允许进入 `retired`，并在 `retired_retention`（默认一分钟）后物理删除。提交前会再次检查 identity、generation、引用、inventory epoch 和 Tor 集合的语义摘要。竞争会变为 no-op；已执行的 Tor 删除通过再次 reconcile 补偿。刷新、来源更新/删除和 retirement 会递增 `inventory_epoch`；发布 working pool 时记录预期 epoch，清单已变化则拒绝发布。

来源删除同样分阶段执行：来源变为 disabled/pending-delete，其候选进入 draining，只有最后一个候选安全回收时才删除来源记录。生命周期与时钟保存在 SQLite，因此 controller 重启无法绕过宽限期、保留期或引用栅栏。

## 自适应锦标赛

清单与 working pool 相互独立。来源刷新最多保存 10,000 个唯一候选；超过限制会拒绝整个刷新并保留 last-known-good。200 个候选的限制只适用于 working pool。

VLESS 队列先执行低成本 fast preflight，再对通过者执行 full probe：8 个 fast worker，deadline 6 秒；4 个 full worker，deadline 20 秒。优先级依次为 unseen、reset-expired、接近边界的 stale、one-success、其他候选、当前 working pool。状态按指纹保存，重复导入后仍然有效。

Tor discovery 使用一个串行 worker，从替换 explorer 到 readiness 和测量的整个过程都由它独占 explorer 配置。Tor 使用独立原始服务端 deadline：fast discovery 5 分钟、full qualification 6 分钟；controller 请求保留现有 response slack。VLESS deadline 和 worker 数量不变，同一时间只能有一个 Tor discovery 进程拥有 explorer。与 VLESS 不同，同优先级的 Tor 候选不按指纹排序，而以当前订阅顺序作为决胜条件。周期性 runtime repair 只比较 warm 配置，在 qualification 期间不会删除临时 explorer；重启后缺失的持久化 warm pool 通过 reconcile 恢复。

- Fast/full 候选失败会增加连续失败计数。
- 第三次失败会封禁候选。
- Full success 清零失败计数。
- 两次 full success 获得 eligibility。
- 保守评分取最近两次成功 full probe 中较差的值。
- 五小时后封禁和计数重置，旧评分仅作为 stale 提示保留。
- Pool 已满时，挑战者必须比最差 working candidate 至少高 15%。

Full probe 检查 Cloudflare/GStatic、YouTube、ChatGPT、OpenAI API、Telegram Web、Telegram MTProto、Instagram 和有界测速。VLESS 只有通过 SOCKS5 UDP association 与 YouTube 完成两次新的 QUIC/TLS 握手后才具备 UDP 资格；仅成功发送 DNS datagram 不再足够。YouTube 关卡要求 `https://www.youtube.com/generate_204` 成功响应；Instagram 要求 `https://www.instagram.com/` 返回低于 400；ChatGPT 不跟随重定向，接受任意 2xx/3xx 或真实源站 403/429；OpenAI 访问 `https://api.openai.com/v1/models`，接受 401、204 或 200；Telegram 同时要求 Web 可用和有效 MTProto 响应。

Active probe 使用独立高优先级 Xray slot、1900 ms deadline 和 75 ms response slack。后台锦标赛不会阻塞故障切换，网络超时能及时作为候选 hard failure 返回。两个独立 HTTP 检查在一个周期内并行运行，不需要第二个外层周期。同一 active slot 还会并行进行轻量 routed-DNS 检查，不执行大文件下载、应用关卡或 QUIC。相邻两次 DNS 失败且 direct control 成功，即确认路由故障。

## QoE 控制循环

QoE 在独立的串行运行循环中执行，不占用 qualification 或 active liveness 队列。Agent 为其分配 4 个独立 Xray slot 和最多 4 个 worker。VLESS 通过隔离的 probe outbound 测量；Tor 为同一候选使用独立探测进程、SOCKS 端口和数据目录，不使用客户端的 serving warm 配置。QoE 不使用 explorer，也不会替换 serving warm 配置。每次探测从 Cloudflare 测速端点精确下载 65,536 字节，deadline 为 10 秒。压缩和缓存关闭，查询参数加入不可预测的加密随机 nonce，响应体仅在固定边界内读取。

调度以候选而非客户端为单位：

- 每轮 QoE 前刷新 WireGuard 字节计数，避免新流量等待五分钟 placement 周期。
- 最近两分钟有客户端流量的已分配路由使用 `qoe.active_interval`（production 为 15 秒）。
- 已分配的空闲路由每 5 分钟探测一次。
- `degraded` 分配使用适用 active/idle 与 degraded 间隔中较短者。
- 无客户端的 `degraded` 路由每分钟探测一次。
- 每种协议最多 3 个 qualified standby VLESS，以及所有已 reconcile 且未分配的 warm Tor，每 15 秒探测一次，直到形成质量晋升所需的完整干净窗口。

TCP/UDP 重叠按 candidate ID 去重，同一候选的第二个 in-flight probe 会合并。下一轮从本轮完成后重新计时，因此慢探测不会积压过期 tick。持续 active 的单条路由约使用 360 MiB/天，idle 路由约 18 MiB/天，promotion standby 约 360 MiB/天，`degraded` recovery 最多 90 MiB/天。同一路由上的客户端数量不会倍增这些估算。

持久化状态机包含 `learning`、`healthy`、`degraded`。前 5 次成功测量建立中位数 baseline。在此之前，TTFB >3 秒或吞吐量 <0.256 Mbit/s 为严重样本。建立 baseline 后，候选连接/TLS/请求/超时/响应体失败，或 TTFB 同时 >1500 ms 且 >2.5 倍 baseline，或吞吐量 <35% baseline，均为坏样本。基础设施样本不进入窗口。最近 5 个有效样本中 3 个坏样本进入 `degraded`，5 个中 4 个好样本恢复。并行的 20 个有效样本可用性窗口在出现两次路由/服务失败后退化，即使失败之间有成功；恢复需等待计数降至 2 以下。好样本以 EWMA 0.1 更新 healthy baseline，`degraded` 时冻结。历史保留 168 小时并分批删除；状态与触发样本在同一 SQLite 事务写入。

对于 VLESS，QoE 会与 TCP 测量并行执行相同的真实 QUIC 检查。连续两次失败只移除 `UDPQualified`，保留 TCP 评分、可用性和新鲜度；连续三次成功恢复 UDP 资格。每次变化立即触发 UDP 重规划，但不迁移正常 TCP，也不重连 WireGuard peer。独立迟滞循环既防止分配仅 DNS 可用的 UDP 路由，也避免单个 QUIC 丢包引发切换。

端点隔离用于区分路由退化与测量器故障。错误 HTTP 状态、异常长度和 malformed response 会立即归类为基础设施问题。路由 transport/TLS/request 错误后执行有界 direct control：直连成功即可确认候选失败。并发 control request 会合并为 single-flight，健康结果复用 30 秒。如果 direct control 失败同时伴随 30 秒内至少三个不同候选的错误，circuit 打开。打开的 circuit 会跳过 QoE 工作且不改变窗口，并在端点恢复前每分钟最多发起一次 direct recovery。服务特定的 active liveness 继续运行。

QoE 迁移目标必须健康状态正常、可用、对所需协议完全 qualified 且处于 `healthy`。其最后有效样本对 active 流量不得超过 2 分钟，对 idle 流量不得超过 10 分钟。TTFB/吞吐量退化使用质量改进迁移：中位有效时间 `TTFB + 64 KiB / throughput` 必须比当前路由至少好 30%，还需 30 分钟最短 dwell、连续 3 个 snapshot 确认和通用 planned-move 限制。单个退化样本或边界抖动会重置 streak。

晋升还要求 5 个干净的 active-cadence 样本：最后一点不超过 40 秒，窗口起点不超过 85 秒，相邻点最大间隔不超过 25 秒。旧的或稀疏的 standby 样本不能证明新主路由稳定。

单次 application gate 失败不会改变分配。QoE 窗口确认且原因为 `qoe_application_gates` 的退化表示客户端服务不可用，而不仅是速度下降。该路由上的所有客户端会立即迁移到具有新鲜 `healthy` QoE 的完全 qualified 替代项，并优先选择 active proof 新鲜的目标；此路径绕过 speedup、dwell、snapshot streak、planned-move 限制，也不受不完整 bounded reserve cover 阻塞。TTFB/吞吐量退化仍使用普通迟滞策略。

主路由、备用路由和紧急选择首先将集合缩小到具有新鲜 `healthy` QoE 的候选。仅在不存在稳定集合时使用 `learning` 作为后备。因此缺少 QoE 容量不会导致 fail-closed，但新发现的高分路由也不会替换已验证路由。

当 `qoe.enabled: false` 时，不创建 monitor、QoE placement trigger 或 scheduler QoE 过滤器；qualification、hard-failure liveness 和普通平衡继续工作。通用 QoE 永远不能替代 full probe 服务关卡：YouTube Web、Instagram、ChatGPT Web、OpenAI API 可接受响应（401、204 或 200）、Telegram Web 和 Telegram MTProto 仍为必需条件。

## 路由分配

只有一个串行 worker 修改数据平面。事件优先级依次为 hard failure、已确认 `qoe_degraded`、手动重分配、客户端生命周期、promotion/demotion、周期平衡。重复事件会合并。调度器使用 weighted rendezvous；非活跃账户不占负载。健康迁移要求 30% 改进、30 分钟 dwell、3 个 snapshot 和目标路由新鲜的 `healthy` QoE；hard failure 绕过这些限制。QoE 关闭时不应用额外 QoE 限制。

新的按评分质量迁移只在周期性 placement 中开始。Promotion、capacity 等服务事件可以立即修复不可用分配，但不会创建额外优化迁移，也不能绕过每轮一次迁移的限制。

分配对客户端具有粘性。平衡主要在初次分配时选择路由；新增客户端和负载波动不会移动健康的现有分配。计划迁移只在稳定改进至少 30% 时允许，并且每轮最多一次 transport move。恢复后的路由不会自动抢回客户端。

确认 hard failure 后优先使用已实体化的 reserve。如果其 active proof 或 runtime handler 已过期，controller 会从共同 Tor/VLESS 池选择最佳合格 TCP 候选，或选择通过 UDP 验证的 VLESS，添加 handler，并只修改受影响客户端。只有确实不存在合格候选时才阻断相应传输；主/备覆盖不完整本身不会导致全局中断。

常规 TCP 主路由优先合格 VLESS。VLESS 主路由的 reserve 优先不同故障域的 VLESS，但若 warm Tor 是唯一故障域安全选项，也可以使用它。紧急替换平等对待合格的 warm VLESS 和 Tor，并按故障域、负载和评分选择；不会等所有 VLESS 都失败后才使用 Tor。UDP 始终只使用 VLESS。

应用顺序为 add outbound → 一次完整替换 routing rules → remove obsolete outbound，中间不会进入 `block`。结果不明确时保留新旧 handler，不确认 generation，重试会幂等地再次应用最终规则。规则替换后 Xray 会保留已接受连接；新流量使用新 handler。如果旧出口本身失效且公网 IP 改变，现有 TCP 会话无法保留：WireGuard 仍保持连接，应用会创建新的 TCP/QUIC 流。

TCP 与 UDP 独立表示。TCP 可使用 VLESS 或 warm Tor，但 Tor 仅提供 TCP。UDP 只有存在单独 qualified VLESS 路由时才允许，否则保持阻断。缺少合适路由时只阻断对应协议。`.ru` 直连规则位于客户端 proxy/block 规则之前。

Tor 预留 3 个 warm 配置和 1 个 explorer。第一个在 fast success 后获得两次成功 full probe 的网桥会成为 eligible，转入 warm 配置并立即触发 placement。其他网桥继续在后台串行 discovery，不占用或替换 warm 配置。Working pool 已满时仍使用共同 promotion threshold：挑战者必须比最差 working candidate 至少高 15%。

目标配置：2 vCPU、1 GiB 内存、最多 50 个 WireGuard 客户端，其中约 10 个同时活跃。VLESS probe Xray 使用互不重叠的范围：4 个 full、8 个 fast、4 个 active 和 4 个 QoE slot。
