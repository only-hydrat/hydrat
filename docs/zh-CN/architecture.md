<p align="center">
  <a href="../architecture.md">Русский</a> · <a href="../en/architecture.md">English</a> · <strong>简体中文</strong>
</p>

# Hydrat 架构

Hydrat 由两个运行在不同网络命名空间中的 Go 进程组成。

- `hydrat agent` 管理 WireGuard、nftables、main/probe Xray、Tor 配置以及所有依赖网络的探测。
- `hydrat controller` 管理来源、自适应锦标赛、调度器、SQLite 和管理界面。

两个进程通过 Unix 套接字上的 HTTP/JSON 通信。管理面板可在 WireGuard 内通过 `http://10.44.0.1:80` 访问：gateway 使用 nftables 将 8080 端口重定向到 80，并用内部令牌签署真实的 WireGuard IP；controller 不信任伪造的代理头。Compose 在主机上只以 `${PORTAL_BIND_ADDRESS:-127.0.0.1}:${PORTAL_PORT:-8088}:8080` 发布面板。外部访问应使用 WireGuard 或带身份验证的 HTTPS 反向代理，不要直接绑定 `0.0.0.0:8088`。

客户端 DNS 与外部 DNS 上游彼此分离。`wireguard.dns` 将 `10.44.0.1` 写入新客户端配置，`xray.dns_resolvers` 定义公共地址池（`1.1.1.1`、`9.9.9.9`、`8.8.8.8`）；单值 `xray.dns_resolver` 仅为兼容性保留。Gateway 命名空间中的独立受监管 dnsmasq 提供该地址：它并行请求独立上游、缓存响应、快速重试丢失的请求，并可在短暂上游故障时返回旧缓存。DNS 不经过客户端已分配的有状态 Xray handler，因此不会随单个 VLESS/XHTTP 会话一起冻结。代价是 DNS 从 gateway 容器直接出站，与客户端选择的 TCP/Tor 路由无关。拦截和配置仅存在于 gateway 命名空间内的 nftables/dnsmasq，不会修改主机或其他容器的 DNS。上游地址不得指回 WireGuard gateway。

QoE 还会通过路由的 SOCKS 代理发送辅助 DNS-over-TCP 请求。失败时，直连控制会检查上游地址池。整个 DNS 池故障属于基础设施问题；如果该路由的 HTTPS 仍正常，仅代理 DNS 失败不会使路由失格，因为客户端 DNS 直接从 gateway 出站。

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

Full probe 检查 Cloudflare/GStatic、YouTube、ChatGPT、OpenAI API、Telegram Web、Telegram MTProto、Instagram 和有界测速。Hydrat 保留订阅中的 flow：标准 `xtls-rprx-vision` 会拦截 UDP/443，使浏览器回退到 HTTPS/TCP；明确指定的 `xtls-rprx-vision-udp443` 则允许 QUIC。标准 Vision 通过 SOCKS5 UDP/53 收到 DNS 应答后才取得其他 UDP 的使用资格；其他 VLESS flow 需要通过 SOCKS5 UDP association 与 YouTube 完成两次新的 QUIC/TLS 握手。YouTube 关卡要求 `https://www.youtube.com/generate_204` 成功响应；Instagram 要求 `https://www.instagram.com/` 返回低于 400；ChatGPT 不跟随重定向，接受任意 2xx/3xx 或真实源站 403/429；OpenAI 访问 `https://api.openai.com/v1/models`，接受 401、204 或 200；Telegram 同时要求 Web 可用和有效 MTProto 响应。

Active probe 使用独立高优先级 Xray slot、1900 ms deadline 和 75 ms response slack。后台锦标赛不会阻塞故障切换，网络超时能及时作为候选 hard failure 返回。Google 和 Cloudflare 的两个独立 HTTP 检查在一个周期内并行运行，不需要第二个外层周期。同一 active slot 还会进行轻量 routed-DNS 检查，不执行大文件下载、应用关卡或 QUIC。单独的 DNS 失败不能证明客户端路由不可用；两个 HTTP 检查也必须失败。

## QoE 控制循环

QoE 在独立的串行运行循环中执行，不占用 qualification 或 active liveness 队列。Agent 为其分配 4 个独立 Xray slot 和最多 4 个 worker。VLESS 通过隔离的 probe outbound 测量；Tor 为同一候选使用独立探测进程、SOCKS 端口和数据目录，不使用客户端的 serving warm 配置。QoE 不使用 explorer，也不会替换 serving warm 配置。每次探测从 Cloudflare 测速端点精确下载 262,144 字节，deadline 为 10 秒。压缩和缓存关闭，查询参数加入不可预测的加密随机 nonce，响应体仅在固定边界内读取。

调度以候选而非客户端为单位：

- 每轮 QoE 前刷新 WireGuard 字节计数，避免新流量等待五分钟 placement 周期。
- 最近两分钟有客户端流量的已分配路由使用 `qoe.active_interval`（production 为 30 秒）。
- 已分配的空闲路由每 5 分钟探测一次。
- `degraded` 分配使用适用 active/idle 与 degraded 间隔中较短者。
- 无客户端的 `degraded` 路由每分钟探测一次。
- 每种协议最多 3 个 qualified standby VLESS，以及所有已 reconcile 且未分配的 warm Tor，每 30 秒探测一次，直到形成质量晋升所需的完整干净窗口。

TCP/UDP 重叠按 candidate ID 去重，同一候选的第二个 in-flight probe 会合并。每秒检查一次待执行任务，每轮启动数量不超过配置的 worker 数量，上限为四个。每个候选从自身探测完成时开始计算间隔，不再等待整批任务结束后的额外暂停。当前分配和实际备用路由与后台任务按 3:1 分配启动机会，空闲额度可互相借用。Standby、恢复检查和 warm Tor 轮流执行，各组优先处理等待最久的候选。持续 active 的单条路由约使用 720 MiB/天，idle 路由约 72 MiB/天，promotion standby 约 720 MiB/天，未分配的 `degraded` 路由恢复探测最多 360 MiB/天。同一路由上的客户端数量不会倍增这些估算。

持久化状态机包含 `learning`、`healthy`、`degraded`。前 5 次成功测量建立中位数 baseline。无论是否已建立 baseline，吞吐量 <1 Mbit/s 都是坏样本；建立前，TTFB >3 秒也属于严重样本。建立后，候选连接/TLS/请求/超时/响应体失败，或 TTFB 同时 >1500 ms 且 >2.5 倍 baseline，或吞吐量 <35% baseline，均为坏样本。基础设施样本不进入窗口。最近 5 个有效样本中 3 个坏样本进入 `degraded`，5 个中 4 个好样本恢复。并行的 20 个有效样本可用性窗口在连续三次路由/服务失败后将路由降级；一次成功测量会重置失败序列。恢复要求最近 5 次中有 4 次好样本。好样本以 EWMA 0.1 更新 healthy baseline，`degraded` 时冻结。历史保留 168 小时并分批删除；状态与触发样本在同一 SQLite 事务写入。

对于 VLESS，QoE 与 TCP 测量并行检查 UDP：标准 `xtls-rprx-vision` 使用 SOCKS5 UDP/53 查询 DNS；其他 flow 对 YouTube 执行两次 QUIC/TLS 握手。客户端 outbound 保留订阅中的 flow。连续两次失败只移除 `UDPQualified`，保留 TCP 评分、可用性和新鲜度；连续三次成功恢复 UDP 资格。每次变化立即触发 UDP 重规划，但不迁移正常 TCP，也不重连 WireGuard peer。独立迟滞循环可避免单个数据包丢失引发切换。

启用 QoE 时，full probe 中单次 UDP 检查失败不会取消此前已确认的 UDP 资格；QoE 会独立确认该传输故障。关闭 QoE 时，full probe 仍会立即更新 UDP 资格。

所有 QoE HTTP 检查都通过配置执行，包括测速端点，不再使用主机直连 HTTP。TTFB 和 256 KiB 下载测速仍然保留。Agent 返回服务和端点的原始结果；HTTP 失败在得到独立对照证据前不算路由故障。Controller 最多使用两个当前可用、已 qualified 的独立配置：fingerprint、route key 和 failure domain 必须不同，端点、DNS、响应接受规则和样本大小策略必须一致。Tor 只能使用已有的 warm profile。同一个必需服务经对照配置访问成功，才确认被测路由的负面结果。两边都失败或没有独立对照时，结果为 `unknown`，既不认定服务已经故障，也不惩罚路由。必需的 QoE 条件仍是 `YouTube && Telegram && (ChatGPT || OpenAI)`。

对照证据最多复用 30 秒，缓存最多保存 64 个候选，每个候选最多 16 条 HTTP 结果。Identity、故障代数或策略变化会使证据失效；新的失败结果会替换之前的成功。缺失的对照检查进入现有四个 worker 和 3:1 调度通道，不递归发起检查，也不让 worker 相互等待。旧结果不会被追溯应用，只对下一次路由检查进行比较。`unknown` 不刷新 `LastValidAt`、不延长 proof 有效期，也不改变 QoE 窗口。主机 HTTP 不可达不再触发暂停整个候选池探索的 circuit。廉价的 active liveness 仍保留独立的直连 DNS 对照。

确认 active hard failure 时，数据库会在同一事务中为实际应用的 primary 保存恢复任务，绑定客户端、传输协议、地址、候选 identity 和代数。紧急处理超时不会丢失任务。恢复优先于普通质量迁移，每次尝试最多 5 秒，重试间隔为 1、2、最多 5 秒；新的紧急故障可以抢占。先检查已安装的 primary/reserve，仅在备用不合格或可能过载时探索工作池。只有 apply/MarkAppliedPlan 确认成功、identity/路由改变、客户端被删除或暂停，或收到并接受节点恢复的成功证据时，任务才会清除。时间流逝和新的 RPC reservation 不能清除任务。TCP 重置仅影响故障客户端已有的连接；仅 UDP 迁移不会重置 TCP。没有替代路由时保留原路由，readiness 保持未就绪。数据库迁移只新增表，不会把历史 failure flag 转成新的恢复任务。

操作员禁用来源也会撤销相关恢复任务，交由现有的来源生命周期逻辑处理，避免恢复循环反复尝试发布已禁用的出口。

如果客户端或来源的并发变更使已应用的路由骨架无法发布，系统会执行有时间上限的完整核对，并禁止质量优化迁移。TCP 重置还必须有当前已确认的故障或与客户端精确匹配的持久恢复任务；计划标为 `hard_failure` 本身并不足够。

Readiness 检查 primary 是否可用以及备用是否符合准入条件，而不是是否仍为首选。出现更优先的 failure domain 不会使健康的已安装备用失效。检查时钟计入排队和 evidence 读取时间，但仍拒绝真正来自未来的时间戳。Critical route 上限和 proof 有效期保持不变。

QoE 迁移目标必须健康状态正常、可用、对所需协议完全 qualified 且处于 `healthy`。最后一个有效样本不得超过 10 分钟，与客户端是否活跃无关。TTFB/相对吞吐量退化使用质量改进迁移：中位有效时间 `TTFB + 256 KiB / throughput` 必须比当前路由至少好 30%，还需 30 分钟最短 dwell、连续 3 个 snapshot 确认和通用 planned-move 限制。单个退化样本或边界抖动会重置 streak。

主动优化路由时，要求最近五个有效样本全部正常，均位于过去 10 分钟内，且采集于最近一次确认故障之后。不再限制相邻样本的最大间隔；过期或来自未来的样本不进入工作窗口。该期限仅控制质量证据的有效期，不会延迟故障检测：独立 active 检查和分配前的新鲜 active proof 保持不变。已确认故障优先于旧 QoE；探测开始后若故障代数发生变化，其结果和 UDP 信号都会被丢弃。

基础设施错误保留安全的原因代码、执行阶段、worker 排队时间、总耗时和 runtime epoch，既不刷新成功证明，也不惩罚节点。运行时处于 draining 或重启阶段时，新的后台 VLESS 探测会延后，按 5、10、20、30 秒的退避间隔重新检查就绪状态。关键 active 通道不会暂停。同一原因的重复 QoE 错误每分钟最多记录一条 `probe_infrastructure` 事件，不包含配置、订阅链接或原始错误消息。

单次 application gate 失败不会改变分配。QoE 窗口确认且原因为 `qoe_application_gates` 的退化表示客户端服务不可用，而不仅是速度下降。该路由上的所有客户端会立即迁移到具有新鲜 `healthy` QoE 的完全 qualified 替代项，并优先选择 active proof 新鲜的目标；此路径绕过 speedup、dwell、snapshot streak、planned-move 限制，也不受不完整 bounded reserve cover 阻塞。吞吐量持续低于 1 Mbit/s 并在最近 5 次中出现 3 次坏样本后，也会立即迁移。TTFB/相对吞吐量退化仍使用普通迟滞策略。

主路由、备用路由和紧急选择首先将集合缩小到具有新鲜 `healthy` QoE 的候选。仅在不存在稳定集合时使用 `learning` 作为后备。因此缺少 QoE 容量不会导致 fail-closed，但新发现的高分路由也不会替换已验证路由。

当 `qoe.enabled: false` 时，不创建 monitor、QoE placement trigger 或 scheduler QoE 过滤器；qualification、hard-failure liveness 和普通平衡继续工作。通用 QoE 永远不能替代 full probe 服务关卡：YouTube Web、Instagram、ChatGPT Web、OpenAI API 可接受响应（401、204 或 200）、Telegram Web 和 Telegram MTProto 仍为必需条件。

## 路由分配

只有一个串行 worker 修改数据平面。事件优先级依次为 hard failure、已确认 `qoe_degraded`、手动重分配、客户端生命周期、promotion/demotion、周期平衡。重复事件会合并。调度器使用 weighted rendezvous；非活跃账户不占负载。健康迁移要求 30% 改进、30 分钟 dwell、3 个 snapshot 和目标路由新鲜的 `healthy` QoE；hard failure 绕过这些限制。QoE 关闭时不应用额外 QoE 限制。

新的按评分质量迁移只在周期性 placement 中开始。Promotion、capacity 等服务事件可以立即修复不可用分配，但不会创建额外优化迁移，也不能绕过每轮一次迁移的限制。

分配对客户端具有粘性。平衡主要在初次分配时选择路由；新增客户端和负载波动不会移动健康的现有分配。计划迁移只在稳定改进至少 30% 时允许，并且每轮最多一次 transport move。恢复后的路由不会自动抢回客户端。

客户端从空闲状态恢复时，如果当前 bootstrap 路由仍有新鲜的验证结果，且已占用的客户端名额少于两个，就保留该路由。过期、失效或拥挤的路由会重新选择。`assignment.migrated` 事件保留原有 `reason`，并增加准确的 placement `trigger`、`from_dormant` 和 `dormant`。仅凭周期性调度触发，不能断定迁移改善了质量。

确认 hard failure 后优先使用已实体化的 reserve。如果其 active proof 或 runtime handler 已过期，controller 会从共同 Tor/VLESS 池选择最佳合格 TCP 候选，或选择通过 UDP 验证的 VLESS，添加 handler，并只修改受影响客户端。只有确实不存在合格候选时才阻断相应传输；主/备覆盖不完整本身不会导致全局中断。

常规 TCP 主路由优先合格 VLESS。VLESS 主路由的 reserve 优先不同故障域的 VLESS，但若 warm Tor 是唯一故障域安全选项，也可以使用它。紧急替换平等对待合格的 warm VLESS 和 Tor，并按故障域、负载和评分选择；不会等所有 VLESS 都失败后才使用 Tor。UDP 始终只使用 VLESS。

应用顺序为 add outbound → 一次完整替换 routing rules → remove obsolete outbound，中间不会进入 `block`。结果不明确时保留新旧 handler，不确认 generation，重试会幂等地再次应用最终规则。规则替换后 Xray 会保留已接受连接；新流量使用新 handler。如果旧出口本身失效且公网 IP 改变，现有 TCP 会话无法保留：WireGuard 仍保持连接，应用会创建新的 TCP/QUIC 流。

确认 hard failure 且成功替换 TCP 路由后，gateway 先应用路由，再仅关闭受影响客户端经由失效 handler 建立的旧 TCP 流。其他客户端、健康 handler 和新流均不受影响。这不是 TCP 会话迁移，也不保证应用重新连接的耗时。计划性的质量或容量迁移不会重置连接。固定版本的 Xray 通过补丁提供此能力，仅 main Xray 开启 Unix 控制套接字（权限 `0600`，父目录 `0700`），不监听网络端口。请求限定为精确的 handler/source，并使用 instance/watermark 标记，防止重试误伤较新的连接；来自旧核心实例的请求会被丢弃。控制接口故障不会撤销已应用的路由：gateway 在本地 applied-state 中保留有界重试队列，不改变 controller 数据库中的路由格式。队列最多保存 2048 个请求，溢出会明确记录。不能直接替换成没有该补丁的上游 Xray 二进制：readiness 要求 flow-control API 可用。

TCP 与 UDP 独立表示。TCP 可使用 VLESS 或 warm Tor，但 Tor 仅提供 TCP。UDP 只有存在单独 qualified VLESS 路由时才允许，否则保持阻断。缺少合适路由时只阻断对应协议。`.ru` 直连规则位于客户端 proxy/block 规则之前。

Tor 预留 3 个 warm 配置和 1 个 explorer。第一个在 fast success 后获得两次成功 full probe 的网桥会成为 eligible，转入 warm 配置并立即触发 placement。其他网桥继续在后台串行 discovery，不占用或替换 warm 配置。Working pool 已满时仍使用共同 promotion threshold：挑战者必须比最差 working candidate 至少高 15%。

目标配置：2 vCPU、1 GiB 内存、最多 50 个 WireGuard 客户端，其中约 10 个同时活跃。VLESS probe Xray 使用互不重叠的范围：4 个 full、8 个 fast、4 个 active 和 4 个 QoE slot。
