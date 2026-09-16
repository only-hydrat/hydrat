# Production operations

## Effective capacity

`GET /api/admin/system` separates inventory from usable route diversity:

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

`working_pool_by_kind` counts current pool members. Effective VLESS capacity
counts only closed failure domains with an available working candidate.
Effective Tor capacity counts non-retiring `warm` profiles. Candidate payloads,
raw endpoints, failure-domain inputs and Tor SOCKS addresses are not returned
by this summary.
`recent_migrations` содержит до 20 последних успешно применённых изменений
assignment. Событие создаётся атомарно вместе с applied generation; причины:
`hard_failure`, `quality_30_percent`, `capacity` и `manual`.

Production acceptance requires at least one effective VLESS failure domain
with TCP and UDP plus at least one warm Tor profile with TCP. Inventory or a
large raw working-pool count alone is not sufficient.

## Routing-state foundation

В текущей state foundation SQLite хранит независимые allocated/applied clocks
для fast, full и active observations, `failure_generation`, lifecycle
кандидата и `inventory_epoch`. Это защищает controller от запоздавших probe,
refresh/qualification races и удаления используемого маршрута. `/api/health`
проверяет только liveness SQLite и gateway-agent и остаётся Docker healthcheck;
`/api/ready` дополнительно отражает readiness controller runtime, включая
active-critical normalization. Потеря внешней ёмкости поэтому даёт 503 только
на `/api/ready` и не создаёт restart loop контейнера.

`inventory.retirement_grace` задаёт минимальное время draining (production
default 15m), `inventory.retired_retention` — паузу между retired и физическим
удалением (default 1m). Collector запускается раз в минуту и обрабатывает
bounded batch до 32 due-кандидатов. Pending-delete source исчезает только после
безопасного удаления последнего кандидата.

Admin API показывает desired/applied generation, но пока не публикует
`inventory_epoch`, полный lifecycle и reference fences. В runtime image также
нет `sqlite3`. Поэтому post-rollout audit открывает live DB только через host
`sqlite3 -readonly` и создаёт отдельный consistent snapshot командой `.backup`:

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

Команды не выбирают encrypted payload, route endpoint или ключи и не открывают
live DB для записи. Временные audit DB и JSON Tor-профилей удаляются trap. Для
наблюдения естественного lifecycle transition повторите блок после очередных
штатных refresh и maintenance и сравните `inventory_epoch`/counts. Read-only
production audit намеренно не создаёт искусственный missing candidate, поэтому
отсутствие строк `draining` или `retired` является допустимым результатом, а
forced transition покрывается store/controller tests.

## Probe runtimes

The agent owns separate background qualification and active-critical Xray
processes. The main-Xray process that serves WireGuard clients is outside both
lifecycles. Background Xray recycles after 250 completed probes. Active Xray
keeps bounded, warmed candidate-to-slot mappings and does not recycle by probe
count; resource, cleanup, readiness and child-exit guards remain active.

Fixed production limits:

| Limit | Value |
| --- | ---: |
| Background probes per epoch | 250 |
| Active probes per epoch | unlimited by count |
| Probe RSS | 256 MiB |
| Probe file descriptors | 512 |
| Drain timeout | 25 seconds |
| Stop timeout | 5 seconds |
| Readiness timeout | 60 seconds |
| Cleanup timeout | 3 seconds |

A recycle closes admission, drains or cancels old leases, stops only the
affected child, starts a replacement, waits for API readiness, increments the
epoch and resets probe control state. Mutations carrying an older epoch fail
closed. Expected safe recycle reasons are `probe_limit` for background only,
plus `rss_limit`, `fd_limit`, `readiness_failure`, `child_exit` and
`cleanup_failure` for either runtime.

The first target snapshot is planned synchronously before readiness. Every
later active cycle probes the last valid snapshot immediately while one bounded
450 ms refresh prepares the next snapshot in parallel. A failed refresh keeps
the last valid snapshot. Snapshots are fenced by applied generation; a changed
primary or reserve is promoted to the critical lane from the committed
assignments on the next tick even while a full refresh is still running. Two
overlapping generations and 32 worker slots cover up to 16 critical routes
without dropping a 2-second tick. Each cycle already performs two independent
HTTP checks; routed DNS requires two consecutive active cycles. The bounded
worst-case DNS pipeline envelope is two 2-second scheduling intervals +
1900 ms server deadline + 75 ms response slack + 1 second planning +
800 ms hard placement = 7775 ms. A complete two-endpoint HTTP failure needs
only one scheduling interval and is bounded by 5775 ms. Repeated
VLESS observations reuse a warmed slot; payload change, eviction or Xray epoch
change is the only reason to configure that slot again.

An expired hard-placement deadline latches readiness red and schedules bounded
startup normalization without terminating the controller. A permanent apply
invariant failure or a lower-priority placement that ignores cancellation is
still fatal because continuing would allow unsafe concurrent mutations.

Inspect the agent directly:

```bash
docker compose exec gateway sh -c \
  'curl --fail --silent --unix-socket /run/hydrat/agent.sock http://localhost/v1/health'
```

Inspect the operator projection through the admin API from the WireGuard
network. Legacy CLI authentication uses the custom password header:

```bash
curl --fail --silent \
  -H "X-Hydrat-Admin-Password: ${HYDRAT_ADMIN_PASSWORD}" \
  http://10.44.0.1/api/admin/system
```

For interactive use, `POST /api/admin/session` exchanges that header for an
in-memory Bearer session; later requests use `Authorization: Bearer <token>`.
The browser holds no password after login, and sessions end on logout, controller
restart, 30 minutes idle, or eight hours absolute lifetime.

Do not paste either response into public reports without checking it for
deployment-specific identifiers.

## VLESS failure-domain recovery

Hydrat derives opaque route and failure-domain identities from normalized VLESS
configuration. Three distinct hard failures in one domain during five minutes
open its circuit for 10 minutes. Placement excludes the whole open domain.
Qualification probes one deterministic current canary; a successful full probe
closes the circuit, while a failed canary extends it.

The failure event, candidate health and probe state are committed atomically.
Delayed events older than a later success are ignored, and a failure wins an
equal-second timestamp tie. This prevents out-of-order active checks from
reopening or closing a recovered domain incorrectly.

## Diagnostic retention

Application logs are UTC-hourly segments under `${DATA_DIR}/logs`. Closed
segments whose complete interval ended at or before `now-72h` are removed at
startup and once per minute. Docker logging is disabled to avoid a second
unbounded copy.

SQLite `events` and `probe_samples` use a stricter record-level rule:

```text
delete where created_at <= now UTC - 72 hours
```

The controller performs this maintenance before its initial source refresh and
then every minute. It deletes each table in indexed transactional batches of
1000 until fewer than 1000 eligible rows remain. Errors are logged and retried
on the next minute. Durable state, QoE history and failure-domain state are
outside this prune.

Useful checks:

```bash
docker compose exec controller sh -c '
  hydrat backup --output /data/controller/backups/retention-check.db
'

docker compose exec gateway sh -c '
  find /data/logs -type f -maxdepth 3 -printf "%TY-%Tm-%TdT%TH:%TM:%TSZ %p\n" |
  sort
'
```

## Release and rollback

Перед deployment сохраните exact prior image и создайте key-aware DB backup.
Accepted runtime — это image, embedded configuration, database, and applied plan.
Значения `ROLLBACK_IMAGE`, `PREVIOUS_IMAGE_ID`, `PREVIOUS_CONFIG_SHA256`,
`BACKUP_PATH`, `APPLIED_PLAN_BACKUP_PATH` и `FAILED_APPLIED_PLAN_PATH` запишите
в release log: они нужны для rollback. `/etc/hydrat/config.yml` запечён в image;
checkout `config/config.yml` используется только как build input exact commit и
не монтируется в работающие containers.

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
test "$(docker image inspect hydrat:latest --format '{{.Id}}')" = \
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

`hydrat restore` здесь пишет только в disposable каталог на SSD-backed
`/data/controller/backups`: до rename он открывает
backup immutable/read-only, выполняет SQLite `quick_check`, проверяет
обязательные tables и расшифровывает sample records master key из
`/data/controller/secrets/master.key`. Затем `hydrat backup` повторно открывает
временную restored DB. Live `/data/controller/hydrat.db` этот validation не
изменяет.

После backup validation:

1. Record current Git commit, both container image IDs, restart/OOM counters
   and desired/applied generation.
2. Build the exact pushed `main` commit; do not build an uncommitted checkout.
3. Recreate **both** `gateway` and `controller` from that same image through
   the mandatory readiness gate:

   ```bash
   docker compose build
   ./scripts/deploy.sh
   ```

   The script first waits for Compose health (`/api/health`), then runs bounded
   in-container checks of `http://127.0.0.1:8080/api/ready`. A release is
   accepted only after 10 consecutive successful checks, so one transient green
   response cannot pass the gate. Defaults are 360 attempts, two seconds between
   attempts, and a two-second curl deadline. The twelve-minute bound covers two
   five-minute full-qualification rounds after a cold source refresh;
   override them only with `HYDRAT_READY_ATTEMPTS`,
   `HYDRAT_READY_CONSECUTIVE_SUCCESSES`, `HYDRAT_READY_DELAY_SECONDS`, and
   `HYDRAT_READY_MAX_TIME_SECONDS`.
4. If the command exits non-zero, the **release rejected** gate has failed:
   do not record a successful deployment and do not delete `ROLLBACK_IMAGE` or
   `BACKUP_PATH`. Keep the previous release artifacts and execute the rollback
   procedure below.
5. Do not use `docker compose down`, image/volume prune, host DNS changes or
   commands against unrelated Compose projects.

### Sticky-routing rollout

Новая routing policy сначала проходит shadow-проверку на копии production DB и
сохранённых событий: решение анализируется без подключения к live agent и без
изменения applied plan. Затем выполняется one-client canary на новом временном
WireGuard peer. Существующие пользовательские peers не используются для canary.

Для canary обязательны следующие инварианты:

- при score/QoE jitter менее трёх последовательных 30%-better snapshots поле
  `recent_migrations` остаётся без новых событий;
- единичный отказ application gates не переносит canary, а подтверждённая
  QoE-окном недоступность YouTube/Telegram/AI сразу переносит всех клиентов
  отказавшего маршрута на свежую healthy альтернативу, предпочитая active-proved;
- добавление canary не меняет assignments существующих клиентов;
- hard failure primary переносит только назначенных ему клиентов;
- устаревший reserve при наличии другого рабочего Tor/VLESS не создаёт
  `BlockTCP`, а рабочий UDP VLESS не создаёт `BlockUDP`;
- VLESS, который отвечает на DNS-over-UDP, но не завершает два QUIC handshake,
  теряет только UDP eligibility после двух QoE observations; TCP assignment и
  WireGuard peer canary при этом не меняются;
- applied generation меняется один раз, а Xray rules не содержат временный
  `hydrat-stage-*-block`;
- WireGuard handshake canary остаётся непрерывным во время смены egress.

После one-client canary требуется 30–60 минут непрерывного YouTube/QUIC и
повторных Telegram/OpenAI запросов. Расширение rollout разрешается только при
нулевом числе необъяснимых migration events. DNS задаётся только внутри Hydrat
gateway/test namespace; DNS хоста не изменяется и Compose-конфигурации других
проектов не затрагиваются.

After deployment verify:

- both containers are healthy and use SSD-backed data;
- both containers use the same expected Hydrat image ID;
- both embedded `/etc/hydrat/config.yml` digests equal the release digest;
- desired generation equals applied generation;
- the read-only routing-state audit above passes;
- source refresh and VLESS/Tor qualification continue;
- effective VLESS and Tor capacity are non-zero;
- YouTube, Telegram, ChatGPT and the exact OpenAI API `401` gate pass through
  assigned routes;
- probe RSS/FD stay below fixed thresholds;
- cgroup `oom`/`oom_kill` counters and kernel OOM baseline do not increase;
- an active WireGuard client keeps traffic during a probe-only recycle;
- two complete probe epochs finish without a no-op generation increase.

### Disposable production-tunnel acceptance

Container health and direct SOCKS checks do not prove the client path. Create a
new temporary WireGuard peer through `POST /api/admin/clients`, download its
`/api/admin/clients/{id}/config`, and use that config only in a disposable
network namespace or privileged test container. Never reuse an existing peer:
that would steal its WireGuard handshake and interrupt the owner.

After the temporary peer has a non-empty TCP and UDP primary/reserve mapping,
exercise through that namespace:

```bash
curl --fail --show-error --max-time 10 https://www.youtube.com/generate_204
curl --fail --show-error --max-time 10 https://web.telegram.org/
curl --output /dev/null --silent --show-error --max-time 10 \
  --write-out 'openai=%{http_code} total=%{time_total}\n' \
  https://api.openai.com/v1/models
curl --fail --output /dev/null --show-error --max-time 60 \
  'https://speed.cloudflare.com/__down?bytes=10485760'
```

Repeat the small requests while active generations overlap. Verify DNS through
the peer's configured resolver, desired/applied generation stability, no new
clustered `candidate_hard_failure`, and no route interruption during an active
probe-runtime recycle. After the test, delete the temporary peer through
`DELETE /api/admin/clients/{id}` and remove the namespace/container and config
file. Also require `GET /api/admin/profiles` to show controller-visible warm Tor
profiles and the routing-state audit to show non-empty TCP mappings after any
gateway restart.

Rollback schema/state foundation всегда восстанавливает оба артефакта. Сначала
проверьте записанные значения и остановите **оба** Hydrat service. Пока
`gateway` и `controller` остановлены, one-off controller из exact prior image
восстанавливает pre-deployment DB. Только после успешного restore оба service
recreate/start из того же image:

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

docker image tag "$ROLLBACK_IMAGE" hydrat:latest
test "$(docker image inspect hydrat:latest --format '{{.Id}}')" = \
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

Старый gateway никогда не запускается с несовместимым snapshot нового
dataplane: snapshot отклонённого релиза сохраняется в
`FAILED_APPLIED_PLAN_PATH`, а exact pre-deployment plan восстанавливается до
старта. Старый controller никогда не запускается на новой DB. Restore сохраняет
заменённую DB как `/data/controller/hydrat.db.before-restore-<UTC timestamp>`,
но rollback artifact остаётся указанный `BACKUP_PATH`. Команды service-scoped:
они не останавливают другие Compose projects и не меняют host DNS.
Embedded config возвращается вместе с exact prior image; host checkout не
копируется внутрь rollback image. После старта дополнительно проверьте
controller-visible Tor profiles, non-empty TCP assignments и реальный запрос
через disposable WireGuard peer.
Rollback намеренно не вызывает `scripts/deploy.sh`: предыдущий image может не
иметь `/api/ready`, который обязателен только для приёмки новой версии.
