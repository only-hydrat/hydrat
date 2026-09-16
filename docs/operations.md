<p align="center">
  <strong>Русский</strong> · <a href="en/operations.md">English</a> · <a href="zh-CN/operations.md">简体中文</a>
</p>

# Эксплуатация в production

## Эффективная ёмкость

`GET /api/admin/system` разделяет размер inventory и реально доступное разнообразие маршрутов:

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

`working_pool_by_kind` считает текущих участников пула. Эффективная ёмкость
VLESS учитывает только закрытые failure domain с доступным рабочим кандидатом.
Эффективная ёмкость Tor учитывает `warm`-профили, не находящиеся в retirement.
Этот summary не возвращает payload кандидатов, исходные endpoint, входы
failure domain и SOCKS-адреса Tor.
`recent_migrations` содержит до 20 последних успешно применённых изменений
assignment. Событие создаётся атомарно вместе с applied generation; причины:
`hard_failure`, `quality_30_percent`, `capacity` и `manual`.

Для приёмки production нужен минимум один эффективный failure domain VLESS с
TCP и UDP и минимум один warm-профиль Tor с TCP. Одного inventory или большого
исходного значения working pool недостаточно.

## Основа состояния маршрутизации

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

## Среды выполнения probe

Agent владеет отдельными Xray-процессами для background qualification и
active-critical. Main Xray, обслуживающий клиентов WireGuard, не входит ни в
один из этих lifecycle. Background Xray пересоздаётся после 250 завершённых
probe. Active Xray хранит bounded прогретые сопоставления candidate-to-slot и
не пересоздаётся по счётчику probe; ограничения ресурсов, cleanup, readiness и
child-exit продолжают действовать.

Фиксированные production-лимиты:

| Лимит | Значение |
| --- | ---: |
| Background probe за epoch | 250 |
| Active probe за epoch | без ограничения по количеству |
| Probe RSS | 256 MiB |
| Probe file descriptors | 512 |
| Drain timeout | 25 секунд |
| Stop timeout | 5 секунд |
| Readiness timeout | 60 секунд |
| Cleanup timeout | 3 секунды |

Recycle закрывает admission, дожидается или отменяет старые lease, останавливает
только затронутый дочерний процесс, запускает замену, ждёт готовности API,
увеличивает epoch и сбрасывает состояние управления probe. Изменения со старым
epoch завершаются fail-closed. Ожидаемые безопасные причины recycle:
`probe_limit` только для background, а также `rss_limit`, `fd_limit`,
`readiness_failure`, `child_exit` и `cleanup_failure` для обеих сред.

Первый snapshot целей планируется синхронно до readiness. Каждый следующий
active-цикл немедленно проверяет последний валидный snapshot, а один bounded
refresh на 450 ms параллельно готовит следующий. Ошибка refresh сохраняет
последний валидный snapshot. Snapshot защищены applied generation; изменившийся
primary или reserve на следующем tick переводится из committed assignments в
critical lane, даже если полный refresh ещё выполняется. Два перекрывающихся
generation и 32 worker slot покрывают до 16 critical routes без пропуска
двухсекундного tick. Каждый цикл уже выполняет две независимые HTTP-проверки;
routed DNS требует двух последовательных active-циклов. Худший bounded pipeline
DNS: два интервала планирования по 2 секунды + server deadline 1900 ms + response
slack 75 ms + planning 1 секунда + hard placement 800 ms = 7775 ms. Полный
двухendpointный HTTP failure требует одного интервала и ограничен 5775 ms.
Повторные VLESS observation используют прогретый slot; повторная конфигурация
нужна только при изменении payload, eviction или epoch Xray.

Истёкший hard-placement deadline фиксирует readiness в красном состоянии и
планирует bounded startup normalization, не завершая controller. Постоянное
нарушение apply invariant или низкоприоритетный placement, игнорирующий отмену,
остаётся fatal: продолжение допустило бы небезопасные конкурентные изменения.

Прямая проверка agent:

```bash
docker compose exec gateway sh -c \
  'curl --fail --silent --unix-socket /run/hydrat/agent.sock http://localhost/v1/health'
```

Проверка operator projection через admin API из сети WireGuard. Legacy CLI
authentication использует специальный заголовок пароля:

```bash
curl --fail --silent \
  -H "X-Hydrat-Admin-Password: ${HYDRAT_ADMIN_PASSWORD}" \
  http://10.44.0.1/api/admin/system
```

Для интерактивной работы `POST /api/admin/session` обменивает этот заголовок на
Bearer-сессию в памяти; дальнейшие запросы используют
`Authorization: Bearer <token>`. После входа браузер не хранит пароль. Сессия
завершается при logout, restart controller, 30 минутах простоя или после восьми
часов абсолютного времени жизни.

Не вставляйте ответы в публичные отчёты без проверки deployment-specific ID.

## Восстановление failure domain VLESS

Hydrat выводит непрозрачные identity маршрута и failure domain из нормализованной
конфигурации VLESS. Три разных hard failure в одном domain за пять минут
открывают circuit на 10 минут. Placement исключает весь открытый domain.
Qualification проверяет один детерминированно выбранный текущий canary:
успешный full probe закрывает circuit, неуспешный продлевает его.

Failure event, health кандидата и probe state коммитятся атомарно. Запоздавшие
события старше последующего success игнорируются; при одинаковой секунде
timestamp побеждает failure. Это не позволяет out-of-order active-проверкам
ошибочно открыть или закрыть восстановленный domain.

## Хранение диагностических данных

Журналы приложения хранятся часовыми UTC-сегментами в `${DATA_DIR}/logs`.
Закрытые сегменты, полный интервал которых завершился не позднее `now-72h`,
удаляются при запуске и затем раз в минуту. Docker logging отключён, чтобы не
создавать вторую неограниченную копию.

SQLite `events` и `probe_samples` используют более строгое правило для записей:

```text
delete where created_at <= now UTC - 72 hours
```

Controller выполняет maintenance до первого refresh источников, а затем каждую
минуту. Каждая таблица очищается индексированными транзакционными batch по 1000
строк, пока подходящих строк не останется меньше 1000. Ошибки журналируются и
повторяются через минуту. Durable state, история QoE и состояние failure domain
этим prune не затрагиваются.

Полезные проверки:

```bash
docker compose exec controller sh -c '
  hydrat backup --output /data/controller/backups/retention-check.db
'

docker compose exec gateway sh -c '
  find /data/logs -type f -maxdepth 3 -printf "%TY-%Tm-%TdT%TH:%TM:%TSZ %p\n" |
  sort
'
```

## Выпуск и откат

Перед deployment сохраните точный предыдущий image и создайте backup БД с
проверкой ключа. Принятый runtime состоит из image, встроенной конфигурации,
database и applied plan.
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

1. Запишите текущий Git commit, ID image обоих контейнеров, счётчики restart/OOM
   и desired/applied generation.
2. Соберите точный commit, отправленный в `main`; не собирайте checkout с
   незакоммиченными изменениями.
3. Пересоздайте **оба** сервиса, `gateway` и `controller`, из одного image через
   обязательный readiness gate:

   ```bash
   docker compose build
   ./scripts/deploy.sh
   ```

   Скрипт сначала ждёт Compose health (`/api/health`), затем выполняет bounded
   проверки `http://127.0.0.1:8080/api/ready` внутри контейнера. Release
   принимается только после 10 последовательных успехов, поэтому единичный
   кратковременный зелёный ответ не проходит gate. По умолчанию выполняется до
   360 попыток с интервалом 2 секунды и deadline curl 2 секунды. Ограничение в
   12 минут покрывает два пятиминутных full-qualification цикла после холодного
   refresh источников. Переопределять значения можно только через
   `HYDRAT_READY_ATTEMPTS`, `HYDRAT_READY_CONSECUTIVE_SUCCESSES`,
   `HYDRAT_READY_DELAY_SECONDS` и `HYDRAT_READY_MAX_TIME_SECONDS`.
4. Ненулевой exit code означает отказ gate **release rejected**: не отмечайте
   deployment успешным и не удаляйте `ROLLBACK_IMAGE` или `BACKUP_PATH`.
   Сохраните артефакты предыдущего release и выполните rollback ниже.
5. Не используйте `docker compose down`, prune image/volume, изменение DNS хоста
   или команды для посторонних Compose projects.

### Развёртывание sticky routing

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

После deployment проверьте:

- оба контейнера healthy и используют данные на SSD;
- оба контейнера используют один ожидаемый ID image Hydrat;
- digest встроенного `/etc/hydrat/config.yml` в обоих контейнерах совпадает с
  release digest;
- desired generation равен applied generation;
- приведённый выше read-only audit состояния маршрутизации проходит;
- refresh источников и qualification VLESS/Tor продолжаются;
- эффективная ёмкость VLESS и Tor ненулевая;
- YouTube, Telegram, ChatGPT и точный gate OpenAI API с ответом `401` проходят
  через назначенные маршруты;
- RSS/FD probe остаются ниже фиксированных порогов;
- счётчики cgroup `oom`/`oom_kill` и baseline OOM ядра не растут;
- активный клиент WireGuard сохраняет трафик во время recycle только probe;
- два полных epoch probe завершаются без no-op увеличения generation.

### Приёмка через одноразовый production-туннель

Container health и прямые SOCKS-проверки не доказывают клиентский путь. Создайте
новый временный WireGuard peer через `POST /api/admin/clients`, скачайте его
`/api/admin/clients/{id}/config` и используйте конфигурацию только в одноразовом
network namespace или привилегированном test container. Никогда не используйте
существующий peer: это перехватит его WireGuard handshake и прервёт связь владельца.

После появления у временного peer непустых TCP и UDP primary/reserve mapping
выполните через этот namespace:

```bash
curl --fail --show-error --max-time 10 https://www.youtube.com/generate_204
curl --fail --show-error --max-time 10 https://web.telegram.org/
curl --output /dev/null --silent --show-error --max-time 10 \
  --write-out 'openai=%{http_code} total=%{time_total}\n' \
  https://api.openai.com/v1/models
curl --fail --output /dev/null --show-error --max-time 60 \
  'https://speed.cloudflare.com/__down?bytes=10485760'
```

Повторяйте небольшие запросы при перекрывающихся active generation. Проверьте DNS
через resolver из конфигурации peer, стабильность desired/applied generation,
отсутствие новых групп `candidate_hard_failure` и отсутствие разрыва маршрута
во время recycle active probe-runtime. После теста удалите временный peer через
`DELETE /api/admin/clients/{id}`, затем namespace/container и файл конфигурации.
Кроме того, `GET /api/admin/profiles` должен показывать видимые controller warm
профили Tor, а audit состояния маршрутизации — непустые TCP mapping после любого
restart gateway.

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
