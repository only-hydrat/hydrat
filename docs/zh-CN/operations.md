<p align="center">
  <a href="../operations.md">Русский</a> · <a href="../en/operations.md">English</a> · <strong>简体中文</strong>
</p>

# 生产环境运维

## 有效容量

`GET /api/admin/system` 将清单规模与实际可用的路由多样性分开显示：

```json
{
  "working_pool_by_kind": {
    "vless": 0,
    "tor_bridge": 0
  },
  "effective_capacity": {
    "vless_failure_domains": 0,
    "tor_warm_profiles": 0
  },
  "probe_runtime": {
    "status": "ready",
    "epoch": 1,
    "rss_bytes": 0,
    "fd_count": 0,
    "completed_probes": 0,
    "recycle_count": 0
  },
  "active_probe_runtime": {
    "status": "ready",
    "epoch": 1,
    "rss_bytes": 0,
    "fd_count": 0,
    "completed_probes": 0,
    "recycle_count": 0
  },
  "recent_migrations": [
    {
      "kind": "assignment.migrated",
      "client_id": "client-id",
      "candidate_id": "candidate-id",
      "message": "{\"transport\":\"tcp\",\"from\":\"old\",\"to\":\"new\",\"reason\":\"hard_failure\"}"
    }
  ]
}
```

`working_pool_by_kind` 统计当前池成员。有效 VLESS 容量只统计包含可用工作候选且 circuit 已关闭的故障域。有效 Tor 容量统计未进入 retirement 的 `warm` 配置。该摘要不会返回候选载荷、原始端点、故障域输入或 Tor SOCKS 地址。

`recent_migrations` 最多包含最近 20 次成功应用的分配变化。事件与 applied generation 在同一事务中写入；原因包括 `hard_failure`、`quality_30_percent`、`capacity` 和 `manual`。

生产验收要求至少一个同时支持 TCP 与 UDP 的有效 VLESS 故障域，以及至少一个支持 TCP 的 warm Tor 配置。只有大量清单条目或原始 working-pool 计数并不足够。

## 路由状态基础

当前状态基础在 SQLite 中保存 fast、full、active observation 各自独立的 allocated/applied 时钟、`failure_generation`、候选生命周期和 `inventory_epoch`。这可防止迟到探测、refresh/qualification 竞争以及仍在使用的路由被删除。`/api/health` 只检查 SQLite 与 gateway-agent 存活状态，并继续作为 Docker healthcheck；`/api/ready` 还反映 controller 运行时就绪状态，包括 active-critical normalization。因此外部容量丢失只会让 `/api/ready` 返回 503，不会触发容器重启循环。

`inventory.retirement_grace` 设置最短 draining 时间（production 默认 15 分钟）；`inventory.retired_retention` 设置 retired 到物理删除之间的等待时间（默认 1 分钟）。Collector 每分钟运行一次，每次最多处理 32 个到期候选。Pending-delete 来源只有在最后一个候选安全删除后才会消失。

Admin API 会显示 desired/applied generation，但暂不公开 `inventory_epoch`、完整生命周期和引用栅栏。运行镜像也不包含 `sqlite3`。因此部署后审计只通过主机上的 `sqlite3 -readonly` 打开 live DB，并用 `.backup` 创建独立一致性快照：

```bash
set -eu
command -v sqlite3 >/dev/null
sqlite3 -readonly :memory: \
  "SELECT CASE WHEN readfile('/etc/hostname') IS NULL THEN 0 ELSE 1 END" |
  grep -Fx 1

CONTROLLER_ID=$(docker compose ps -q controller)
test -n "$CONTROLLER_ID"
DATA_ROOT=$(docker inspect "$CONTROLLER_ID" --format \
  '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}')
test -n "$DATA_ROOT"
LIVE_DB="${DATA_ROOT}/controller/hydrat.db"
test -r "$LIVE_DB"

PROFILES_JSON=
AUDIT_DB=$(mktemp /tmp/hydrat-state-audit.XXXXXX.db)
cleanup_state_audit() {
  for path in "${AUDIT_DB:-}" "${PROFILES_JSON:-}"; do
    case "$path" in
      /tmp/hydrat-state-audit.*.db|/tmp/hydrat-state-profiles.*.json)
        rm -f -- "$path"
        ;;
      "")
        ;;
      *)
        printf 'refusing to remove unexpected audit path: %s\n' "$path" >&2
        ;;
    esac
  done
}
trap cleanup_state_audit EXIT

sqlite3 -readonly "$LIVE_DB" ".backup '$AUDIT_DB'"
test -s "$AUDIT_DB"

PROFILES_JSON=$(mktemp /tmp/hydrat-state-profiles.XXXXXX.json)
docker compose exec -T gateway sh -c \
  'curl --fail --silent --unix-socket /run/hydrat/agent.sock http://localhost/v1/profiles' \
  >"$PROFILES_JSON"
test -s "$PROFILES_JSON"

CHECKS=$(
  sqlite3 -readonly -batch -bail -noheader -separator ' ' \
    -cmd '.parameter init' \
    -cmd ".parameter set @profiles_path '$PROFILES_JSON'" \
    "$AUDIT_DB" <<'SQL'
WITH plan_refs(candidate_id, origin) AS (
  SELECT
    CASE
      WHEN instr(json_extract(item.value, '$.id'), '-profile-') > 0
      THEN substr(
        json_extract(item.value, '$.id'),
        1,
        instr(json_extract(item.value, '$.id'), '-profile-') - 1
      )
      ELSE json_extract(item.value, '$.id')
    END,
    'desired_plan'
  FROM plan_state, json_each(
    CAST(desired_plan AS TEXT), '$.outbounds'
  ) AS item
  UNION ALL
  SELECT
    CASE
      WHEN instr(json_extract(item.value, '$.id'), '-profile-') > 0
      THEN substr(
        json_extract(item.value, '$.id'),
        1,
        instr(json_extract(item.value, '$.id'), '-profile-') - 1
      )
      ELSE json_extract(item.value, '$.id')
    END,
    'applied_plan'
  FROM plan_state, json_each(
    CAST(applied_plan AS TEXT), '$.outbounds'
  ) AS item
),
refs(candidate_id, origin) AS (
  SELECT tcp_outbound, 'assignment_tcp'
  FROM assignments WHERE tcp_outbound <> ''
  UNION ALL
  SELECT udp_outbound, 'assignment_udp'
  FROM assignments WHERE udp_outbound <> ''
  UNION ALL
  SELECT candidate_id, 'working_pool'
  FROM candidate_probe_state
  WHERE candidate_id <> '' AND (in_working_pool = 1 OR draining = 1)
  UNION ALL
  SELECT candidate_id, origin FROM plan_refs
)
SELECT
  (SELECT COALESCE(max(version), 0) FROM schema_migrations),
  (SELECT epoch FROM inventory_state WHERE singleton = 1),
  (SELECT desired_generation FROM plan_state WHERE singleton = 1),
  (SELECT applied_generation FROM plan_state WHERE singleton = 1),
  (
    SELECT count(*) FROM candidate_probe_state
    WHERE fast_result_seq < 0 OR fast_applied_seq < 0
       OR fast_applied_seq > fast_result_seq
  ) + (
    SELECT count(*) FROM candidate_health
    WHERE full_result_seq < 0 OR full_applied_seq < 0
       OR full_applied_seq > full_result_seq
       OR active_result_seq < 0 OR active_applied_seq < 0
       OR active_applied_seq > active_result_seq
       OR failure_generation < 0
  ),
  (
    SELECT count(*)
    FROM refs
    JOIN candidates ON candidates.id = refs.candidate_id
    WHERE candidates.lifecycle = 'retired'
  ),
  (
    SELECT count(*)
    FROM json_each(
      CAST(readfile(@profiles_path) AS TEXT), '$.profiles'
    ) AS profile
    JOIN candidates
      ON candidates.id = json_extract(profile.value, '$.candidate_id')
    WHERE candidates.lifecycle = 'retired'
  );
SQL
)
set -- $CHECKS
test "$#" -eq 7
test "$1" -ge 10
test "$2" -ge 0
test "$3" = "$4"
test "$5" -eq 0
test "$6" -eq 0
test "$7" -eq 0

sqlite3 -readonly -header -column "$AUDIT_DB" <<'SQL'
SELECT
  epoch AS inventory_epoch
FROM inventory_state
WHERE singleton = 1;

SELECT
  lifecycle,
  count(*) AS candidates,
  sum(drain_after IS NOT NULL AND drain_after <= unixepoch()) AS drain_due,
  sum(retired_at IS NOT NULL AND retired_at <= unixepoch() - 60) AS delete_due
FROM candidates
GROUP BY lifecycle
ORDER BY lifecycle;
SQL
```

这些命令不会读取加密载荷、路由端点或密钥，也不会以写入方式打开 live DB。Trap 会删除临时 audit DB 和 Tor 配置 JSON。要观测自然生命周期变化，请在正常 refresh 与 maintenance 周期后重复运行，并比较 `inventory_epoch` 与计数。只读生产审计不会人为制造缺失候选，因此没有 `draining` 或 `retired` 行也是有效结果；强制转换由 store/controller 测试覆盖。

## 探测运行时

Agent 分别管理后台 qualification 与 active-critical Xray 进程。服务 WireGuard 客户端的 main Xray 不属于这两个生命周期。Background Xray 每完成 250 次探测后轮换。Active Xray 保留有界的预热 candidate-to-slot 映射，不按探测次数轮换；资源、清理、就绪及子进程退出保护仍然生效。

固定生产限制：

| 限制 | 值 |
| --- | ---: |
| 每个 epoch 的后台探测 | 250 |
| 每个 epoch 的 active 探测 | 不按数量限制 |
| 探测 RSS | 256 MiB |
| 探测文件描述符 | 512 |
| Drain 超时 | 25 秒 |
| Stop 超时 | 5 秒 |
| Readiness 超时 | 60 秒 |
| Cleanup 超时 | 3 秒 |

轮换会关闭新任务准入、排空或取消旧 lease，只停止受影响的子进程，启动替代进程，等待 API ready，递增 epoch 并重置探测控制状态。携带旧 epoch 的更改会故障关闭。安全轮换原因包括仅用于后台的 `probe_limit`，以及两个运行时均可能出现的 `rss_limit`、`fd_limit`、`readiness_failure`、`child_exit` 和 `cleanup_failure`。

第一个目标快照在 ready 前同步规划。之后每个 active 周期立即探测最后一个有效快照，同时用一个有界 450 ms refresh 并行准备下一快照。刷新失败时保留最后有效快照。快照受 applied generation 栅栏保护；主路由或备用路由变化后，即使 full refresh 仍在运行，也会在下一 tick 从已提交 assignments 提升到 critical lane。两个重叠 generation 和 32 个 worker slot 可覆盖最多 16 条关键路由且不丢失 2 秒 tick。每个周期已执行两个独立 HTTP 检查；routed DNS 需要连续两个 active 周期。DNS 最坏有界流水线为两个 2 秒调度间隔 + 1900 ms 服务端 deadline + 75 ms response slack + 1 秒规划 + 800 ms hard placement = 7775 ms。双端点 HTTP 完全失败只需一个调度间隔，上限 5775 ms。重复 VLESS observation 会复用预热 slot；只有载荷变化、驱逐或 Xray epoch 变化才会重新配置。

Hard-placement deadline 到期会将 readiness 锁定为红色，并安排有界启动 normalization，而不会终止 controller。永久 apply invariant 失败或忽略取消的低优先级 placement 仍属致命错误，因为继续运行会允许不安全的并发更改。

直接检查 agent：

```bash
docker compose exec gateway sh -c \
  'curl --fail --silent --unix-socket /run/hydrat/agent.sock http://localhost/v1/health'
```

从 WireGuard 网络通过 admin API 检查运维视图。旧版 CLI 身份验证使用自定义密码头：

```bash
curl --fail --silent \
  -H "X-Hydrat-Admin-Password: ${HYDRAT_ADMIN_PASSWORD}" \
  http://10.44.0.1/api/admin/system
```

交互使用时，`POST /api/admin/session` 会将该 header 换成内存中的 Bearer 会话；后续请求使用 `Authorization: Bearer <token>`。登录后浏览器不再保留密码；注销、controller 重启、空闲 30 分钟或达到 8 小时绝对时限都会结束会话。

将任何响应粘贴到公开报告前，必须检查其中是否包含部署特定标识符。

## VLESS 故障域恢复

Hydrat 从规范化 VLESS 配置派生不透明的路由和故障域标识。同一故障域在 5 分钟内出现 3 次不同 hard failure 后，circuit 会打开 10 分钟，placement 排除整个故障域。Qualification 会确定性选择一个当前 canary；成功 full probe 关闭 circuit，失败则延长打开时间。

故障事件、候选健康和探测状态原子提交。早于后续成功的延迟事件会被忽略；时间戳同秒时故障优先。这可防止乱序 active 检查错误地重新打开或关闭已恢复故障域。

## 诊断数据保留

应用日志按 UTC 小时分段，位于 `${DATA_DIR}/logs`。完整时间区间在 `now-72h` 之前结束的已关闭分段，会在启动时及之后每分钟删除。Docker logging 已关闭，以避免产生第二份无界副本。

SQLite 的 `events` 和 `probe_samples` 使用更严格的逐记录规则：

```text
delete where created_at <= now UTC - 72 hours
```

Controller 在首次来源刷新前执行该维护，之后每分钟执行一次。每张表按索引事务批次每次删除 1000 行，直到符合条件的行少于 1000。错误会记录，并在下一分钟重试。持久状态、QoE 历史和故障域状态不在此次清理范围内。

实用检查命令：

```bash
docker compose exec controller sh -c '
  hydrat backup --output /data/controller/backups/retention-check.db
'

docker compose exec gateway sh -c '
  find /data/logs -type f -maxdepth 3 -printf "%TY-%Tm-%TdT%TH:%TM:%TSZ %p\n" |
  sort
'
```

## 发布与回滚

部署前请保留精确的旧镜像，并创建可使用主密钥验证的数据库备份。已验收运行状态由镜像、内嵌配置、数据库和已应用计划共同组成。请将 `ROLLBACK_IMAGE`、`PREVIOUS_IMAGE_ID`、`PREVIOUS_CONFIG_SHA256`、`BACKUP_PATH`、`APPLIED_PLAN_BACKUP_PATH` 和 `FAILED_APPLIED_PLAN_PATH` 记录到发布日志；回滚需要这些值。`/etc/hydrat/config.yml` 已烘焙进镜像。Checkout 中的 `config/config.yml` 仅在从源码构建时作为输入，不会挂载到运行容器。

```bash
set -eu
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
GATEWAY_ID=$(docker compose ps -q gateway)
CONTROLLER_ID=$(docker compose ps -q controller)
test -n "$GATEWAY_ID"
test -n "$CONTROLLER_ID"
PREVIOUS_IMAGE_ID=$(docker inspect "$GATEWAY_ID" --format '{{.Image}}')
test "$(docker inspect "$CONTROLLER_ID" --format '{{.Image}}')" = \
  "$PREVIOUS_IMAGE_ID"
CURRENT_IMAGE_REF=$(docker inspect "$GATEWAY_ID" --format '{{.Config.Image}}')
test -n "$CURRENT_IMAGE_REF"
test "$(docker image inspect "$CURRENT_IMAGE_REF" --format '{{.Id}}')" = \
  "$PREVIOUS_IMAGE_ID"
PREVIOUS_CONFIG_SHA256=$(docker compose exec -T gateway \
  sha256sum /etc/hydrat/config.yml | awk '{print $1}')
test -n "$PREVIOUS_CONFIG_SHA256"
test "$PREVIOUS_CONFIG_SHA256" = "$(docker compose exec -T controller \
  sha256sum /etc/hydrat/config.yml | awk '{print $1}')"
ROLLBACK_IMAGE="hydrat:rollback-${STAMP}"
BACKUP_PATH="/data/controller/backups/predeploy-${STAMP}.db"
APPLIED_PLAN_BACKUP_PATH="/data/agent/applied-plan.predeploy-${STAMP}.json"
FAILED_APPLIED_PLAN_PATH="/data/agent/applied-plan.failed-release-${STAMP}.json"

docker image tag "$PREVIOUS_IMAGE_ID" "$ROLLBACK_IMAGE"
test "$(docker image inspect "$ROLLBACK_IMAGE" --format '{{.Id}}')" = \
  "$PREVIOUS_IMAGE_ID"
test "$PREVIOUS_CONFIG_SHA256" = "$(docker run --rm \
  --entrypoint sha256sum "$ROLLBACK_IMAGE" /etc/hydrat/config.yml | \
  awk '{print $1}')"

docker compose exec -T controller \
  hydrat backup --output "$BACKUP_PATH"
docker compose exec -T controller test -s "$BACKUP_PATH"

docker compose exec -T gateway sh -eu -c '
source=/data/agent/applied-plan.json
backup=$1
test -s "$source"
test ! -e "$backup"
cp -- "$source" "$backup"
chmod 0600 "$backup"
test -s "$backup"
' sh "$APPLIED_PLAN_BACKUP_PATH" </dev/null

docker compose run --rm --no-deps --entrypoint /bin/sh controller \
  -eu -c '
backup_path=$1
tempdir=$(mktemp -d /data/controller/backups/hydrat-backup-validate.XXXXXX)
cleanup() {
  rm -f -- \
    "$tempdir/config.yml" \
    "$tempdir/hydrat.db" \
    "$tempdir/hydrat.db-wal" \
    "$tempdir/hydrat.db-shm" \
    "$tempdir/reopened.db"
  rmdir "$tempdir"
}
trap cleanup EXIT

sed \
  "s#^  database: /data/controller/hydrat.db\$#  database: $tempdir/hydrat.db#" \
  /etc/hydrat/config.yml >"$tempdir/config.yml"
grep -Fqx "  database: $tempdir/hydrat.db" "$tempdir/config.yml"

hydrat restore \
  --config "$tempdir/config.yml" \
  --input "$backup_path"
hydrat backup \
  --config "$tempdir/config.yml" \
  --output "$tempdir/reopened.db"
test -s "$tempdir/reopened.db"
' sh "$BACKUP_PATH"
```

此处 `hydrat restore` 只写入 SSD 上 `/data/controller/backups` 下的一次性目录。Rename 前，它以 immutable/read-only 方式打开备份，运行 SQLite `quick_check`，检查必需表，并使用 `/data/controller/secrets/master.key` 中的主密钥解密样本记录。随后 `hydrat backup` 再次打开临时恢复的数据库。该验证不会修改 live `/data/controller/hydrat.db`。

备份验证后：

1. 记录当前 Git commit、两个容器镜像 ID、restart/OOM 计数及 desired/applied generation。
2. 部署官方发布版本时，在 `.env` 中用 `HYDRAT_IMAGE` 指定目标版本并拉取镜像。开发时使用 `docker-compose.dev.yml` 构建精确 commit；不要构建包含未提交更改的 checkout。
3. 使用同一镜像重新创建 **gateway 和 controller 两个服务**，并通过强制 readiness gate：

   预构建镜像部署（默认）：
   ```bash
   docker compose pull
   ./scripts/deploy.sh
   ```

   从源码本地构建（开发模式）：
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dev.yml build
   HYDRAT_IMAGE=hydrat:dev ./scripts/deploy.sh
   ```

   脚本先等待 Compose health（`/api/health`），再在容器内有界检查 `http://127.0.0.1:8080/api/ready`。只有连续 10 次成功才验收发布，因此一次短暂绿色响应不能通过。默认最多 360 次、间隔 2 秒、curl deadline 2 秒。12 分钟上限可覆盖冷来源刷新后的两轮 5 分钟 full qualification；只有通过 `HYDRAT_READY_ATTEMPTS`、`HYDRAT_READY_CONSECUTIVE_SUCCESSES`、`HYDRAT_READY_DELAY_SECONDS` 和 `HYDRAT_READY_MAX_TIME_SECONDS` 才能覆盖默认值。
4. 命令非零退出表示 **release rejected** gate 失败：不得记录成功部署，也不得删除 `ROLLBACK_IMAGE` 或 `BACKUP_PATH`。保留旧版本制品并执行下述回滚。
5. 不要使用 `docker compose down`、镜像/卷 prune、修改主机 DNS，或对无关 Compose 项目执行命令。

### 粘性路由发布

新路由策略首先在 production DB 副本及保存事件上执行 shadow 检查：分析决策时不连接 live agent，也不修改 applied plan。随后在新建临时 WireGuard peer 上执行单客户端 canary。不得复用现有用户 peer，否则会中断其连接。

Canary 必须满足以下不变量：

- Score/QoE 抖动未达到连续 3 个高出 30% 的 snapshot 时，`recent_migrations` 不出现新事件。
- 单次 application gate 失败不会迁移 canary；QoE 窗口确认 YouTube/Telegram/AI 不可用时，会立即把故障路由上的所有客户端迁移到新鲜 healthy 替代项，并优先 active-proved 目标。
- 添加 canary 不改变现有客户端 assignments。
- 主路由 hard failure 只迁移分配给该路由的客户端。
- 存在其他可用 Tor/VLESS 时，过期 reserve 不会产生 `BlockTCP`；可用 UDP VLESS 不会产生 `BlockUDP`。
- 普通 VLESS 若无法完成两次 QUIC handshake，在两次 QoE observation 后只失去 UDP eligibility。标准 `xtls-rprx-vision` 会有意拒绝 UDP/443，因此改用 DNS-over-UDP 检查。
- Applied generation 只变化一次，Xray 规则不包含临时 `hydrat-stage-*-block`。
- 更换 egress 时 canary 的 WireGuard handshake 保持连续。

单客户端 canary 后，持续运行 YouTube/QUIC 并重复 Telegram/OpenAI 请求 30–60 分钟。只有不存在无法解释的 migration event 时才扩大 rollout。DNS 仅在 Hydrat gateway/test namespace 内配置；不要修改主机 DNS 或其他项目的 Compose 配置。

部署后验证：

- 两个容器均 healthy，且数据位于 SSD；
- 两个容器使用同一预期 Hydrat 镜像 ID；
- 两个容器内嵌的 `/etc/hydrat/config.yml` 摘要均等于发布摘要；
- desired generation 等于 applied generation；
- 上述只读路由状态审计通过；
- 来源刷新及 VLESS/Tor qualification 持续运行；
- 有效 VLESS 和 Tor 容量均非零；
- YouTube、Telegram、ChatGPT 和精确的 OpenAI API `401` gate 可通过已分配路由；
- 探测 RSS/FD 低于固定阈值；
- cgroup `oom`/`oom_kill` 计数与内核 OOM baseline 不增加；
- 仅轮换 probe 时，活跃 WireGuard 客户端流量不中断；
- 两个完整 probe epoch 结束且无无效 generation 增长。

### 一次性生产隧道验收

容器 health 和直连 SOCKS 检查不能证明客户端路径可用。通过 `POST /api/admin/clients` 创建新的临时 WireGuard peer，下载 `/api/admin/clients/{id}/config`，并只在一次性网络命名空间或特权测试容器中使用。绝不要复用现有 peer，否则会抢走其 WireGuard handshake 并中断原用户。

临时 peer 获得非空 TCP 与 UDP 主/备映射后，在该命名空间内执行：

```bash
curl --fail --show-error --max-time 10 https://www.youtube.com/generate_204
curl --fail --show-error --max-time 10 https://web.telegram.org/
curl --output /dev/null --silent --show-error --max-time 10 \
  --write-out 'openai=%{http_code} total=%{time_total}\n' \
  https://api.openai.com/v1/models
curl --fail --output /dev/null --show-error --max-time 60 \
  'https://speed.cloudflare.com/__down?bytes=10485760'
```

在 active generation 重叠期间重复小请求。验证 peer 配置的 resolver 能解析 DNS、desired/applied generation 稳定、不出现新的成组 `candidate_hard_failure`，且 active probe-runtime 轮换期间路由不中断。测试后通过 `DELETE /api/admin/clients/{id}` 删除临时 peer，并删除命名空间/容器和配置文件。还应确认 `GET /api/admin/profiles` 显示 controller 可见的 warm Tor 配置，并且 gateway 重启后路由状态审计仍显示非空 TCP 映射。

状态基础回滚始终恢复数据库与 applied plan 两个制品。先核对记录值并停止 **两个** Hydrat 服务。`gateway` 与 `controller` 均停止后，使用精确旧镜像启动一次性 controller，恢复部署前数据库。只有 restore 成功后，才从同一镜像重新创建并启动两个服务：

```bash
set -eu
: "${ROLLBACK_IMAGE:?set the recorded rollback image tag}"
: "${PREVIOUS_IMAGE_ID:?set the recorded prior image ID}"
: "${PREVIOUS_CONFIG_SHA256:?set the recorded embedded config digest}"
: "${BACKUP_PATH:?set the recorded /data/controller/backups path}"
: "${APPLIED_PLAN_BACKUP_PATH:?set the recorded applied-plan backup path}"
: "${FAILED_APPLIED_PLAN_PATH:?set the recorded failed-plan retention path}"

test "$(docker image inspect "$ROLLBACK_IMAGE" --format '{{.Id}}')" = \
  "$PREVIOUS_IMAGE_ID"
test "$PREVIOUS_CONFIG_SHA256" = "$(docker run --rm \
  --entrypoint sha256sum "$ROLLBACK_IMAGE" /etc/hydrat/config.yml | \
  awk '{print $1}')"

docker compose stop controller gateway
for service in controller gateway; do
  container=$(docker compose ps -aq "$service")
  test -n "$container"
  test "$(docker inspect "$container" --format '{{.State.Running}}')" = false
done

export HYDRAT_IMAGE="${ROLLBACK_IMAGE}"
test "$(docker image inspect "$HYDRAT_IMAGE" --format '{{.Id}}')" = \
  "$PREVIOUS_IMAGE_ID"

docker compose run --rm --no-deps --entrypoint /bin/sh gateway \
  -eu -c '
live=/data/agent/applied-plan.json
backup=$1
failed=$2
test -s "$backup"
if test -e "$live"; then
  test ! -e "$failed"
  mv -- "$live" "$failed"
fi
cp -- "$backup" "$live"
chmod 0600 "$live"
test -s "$live"
' sh "$APPLIED_PLAN_BACKUP_PATH" "$FAILED_APPLIED_PLAN_PATH" </dev/null

docker compose run --rm --no-deps controller \
  restore --input "$BACKUP_PATH" </dev/null

# Rollback image may predate /api/ready. It is an already accepted release,
# so restore it through the Compose health gate instead of the new-release gate.
docker compose up --detach --force-recreate --wait gateway controller
docker compose exec -T controller \
  curl --fail --silent --show-error --max-time 2 \
  http://127.0.0.1:8080/api/health >/dev/null
for service in gateway controller; do
  container=$(docker compose ps -q "$service")
  test -n "$container"
  test "$(docker inspect "$container" --format '{{.Image}}')" = \
    "$PREVIOUS_IMAGE_ID"
  test "$(docker compose exec -T "$service" \
    sha256sum /etc/hydrat/config.yml | awk '{print $1}')" = \
    "$PREVIOUS_CONFIG_SHA256"
done
docker compose ps gateway controller
```

旧 gateway 绝不会带着新数据平面的不兼容快照启动。被拒绝版本的快照保存在 `FAILED_APPLIED_PLAN_PATH`，精确的部署前计划在启动前恢复。旧 controller 绝不会在新数据库上启动。Restore 将被替换数据库保存为 `/data/controller/hydrat.db.before-restore-<UTC timestamp>`，而回滚制品仍是记录的 `BACKUP_PATH`。命令仅针对指定服务，不会停止其他 Compose 项目或修改主机 DNS。内嵌配置随精确旧镜像恢复；主机 checkout 不会复制进回滚镜像。启动后还需检查 controller 可见的 Tor 配置、非空 TCP assignments，并通过一次性 WireGuard peer 发起真实请求。回滚有意不调用 `scripts/deploy.sh`：旧镜像可能没有 `/api/ready`，该端点仅为新版本验收所必需。
