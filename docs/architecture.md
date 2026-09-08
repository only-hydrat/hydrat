# Архитектура Hydrat

Hydrat состоит из двух Go-процессов в разных network namespace.

- `hydrat agent` владеет WireGuard, nftables, main/probe Xray, Tor-профилями и
  всеми network-bound probe.
- `hydrat controller` владеет источниками, adaptive tournament, scheduler,
  SQLite и admin UI.

Процессы общаются по HTTP/JSON через Unix socket. Доступ к панели управления (Portal)
возможен как внутри WireGuard по адресу `http://10.44.0.1:80` (gateway перенаправляет
порт 8080 на 80 через nftables и подписывает реальный WireGuard IP внутренним token;
forged proxy headers controller не доверяет), так и напрямую на хосте через опубликованный
порт `${PORTAL_PORT:-8088}:8080`.
DNS клиентов и внешние DNS upstream разделены. `wireguard.dns` публикует
`10.44.0.1` в новых клиентских профилях, а `xray.dns_resolvers` задаёт пул
публичных адресов (`1.1.1.1`, `9.9.9.9`, `8.8.8.8`); одиночный
`xray.dns_resolver` сохранён для совместимости. В gateway namespace этот адрес
обслуживает отдельный supervised dnsmasq: он отправляет запрос одновременно
независимым upstream, кэширует ответы, быстро повторяет потерянные запросы и
может отдать устаревший кэш при короткой недоступности upstream. DNS не проходит
через stateful Xray handler назначенного клиента и поэтому не замерзает вместе
с отдельной VLESS/XHTTP-сессией. Цена этого решения — DNS egress идёт напрямую
из gateway-контейнера, независимо от выбранного TCP/TOR маршрута клиента.
Перехват и настройка выполняются только nftables/dnsmasq внутри gateway network
namespace; DNS хоста и других контейнеров не изменяется. Ни один upstream не
может указывать обратно на WireGuard gateway.

QoE-проверка каждого TCP-маршрута по-прежнему выполняет DNS-over-TCP запрос к
детерминированно выбранному upstream через отдельный SOCKS маршрута. При ошибке
прямые контрольные запросы параллельно проверяют весь пул: доступность хотя бы
одного upstream доказывает пользовательскую деградацию маршрута, а общий сбой
всего пула не понижает score отдельных маршрутов.
Transparent policy routing в этом namespace использует принадлежащий Hydrat
приоритет `10000`; несовместимое правило с тем же приоритетом останавливает
bootstrap без удаления или изменения чужого правила.

Agent сохраняет applied plan. После restart он ждёт Xray, выполняет add → route
для сохранённой generation и только затем становится ready. Поэтому restart
gateway не требует restart controller, а restart controller не снимает уже
применённые маршруты.

TCP- и UDP-назначения независимы. TCP может использовать VLESS или прогретый
Tor-профиль с одним мостом. UDP использует только прошедший проверку VLESS.
Tor участвует в общем TCP-пуле наравне с VLESS: это не специальный резервный
класс. Если подтверждённый score Tor выше, он может стать primary TCP-маршрутом
клиента; резервом считается роль любого другого пригодного кандидата.
Распознанные домены `.ru`, `.su`, `.xn--p1ai`, а также адреса из `direct_domains` идут напрямую.
Интеллектуальная маршрутизация GeoRules (при `routing.geo_rules.enabled: true`) использует
регулярно обновляемые базы GeoSite и GeoIP (`russia-blocked-geosite` и `russia-blocked-geoip`,
по умолчанию каждые 24h): трафик правил `geosite:category-ru` и `geoip:ru` направляется
напрямую (`direct`), а `geosite:russia-blocked` и `geoip:russia-blocked` принудительно
проксируется. Защита от утечки российского трафика (`routing.disallow_ru_egress: true`) на
этапе pre-probe фильтрации исключает ноды выхода, расположенные в РФ, предотвращая утечку
цензурируемого трафика; состояние сохраняется в конфигурации и файле `routing.json`.
Неизвестный трафик остаётся проксированным; при отсутствии подходящего маршрута применяется
fail-closed. IPv6, NaiveProxy, onion-маршрутизация и автоматическое обновление core не поддерживаются.
Источники управляются через админ-панель. Предпросмотр смешанного ввода принимает
VLESS-ссылки, URL VLESS-подписок, строки Tor-мостов и URL списков мостов.
Tor-мосты `obfs4` и `webtunnel` можно передавать без необязательного префикса
`Bridge`: parser сохраняет их в каноническом виде `Bridge <исходная строка>`.
Неизвестные транспорты, некорректные адреса и fingerprint остаются невалидными.
Секреты шифруются в SQLite. Во время refresh текущие маршруты продолжают
работать, а ошибка обновления сохраняет last-known-good inventory кандидатов.
Внутренний `source_position` использует нумерацию с нуля. Миграция версии 3
задаёт существующим кандидатам fallback-порядок `created_at, id`; успешный
refresh транзакционно заменяет этот fallback актуальным порядком подписки.
Controller потребляет порядок store без сортировки Tor-кандидатов по
fingerprint. Приоритет Tor-очереди учитывает поколение inventory: текущие
unseen-кандидаты выполняются до retry-кандидатов, а внутри каждого одинакового
приоритета сохраняется `source_position`. Кандидат из старого снимка, удалённый
конкурентным refresh, пропускается без остановки цикла; следующий цикл строится
из нового inventory и ставит новые unseen-кандидаты перед retries.

## Causal observation state

Fast, full и active probe имеют независимые persisted clocks. Перед сетевым
RPC controller резервирует stage-specific sequence: `*_result_seq` — это
allocated clock, а `*_applied_seq` — последний атомарно применённый результат.
Резервация N+1 сама по себе не отменяет выполняющийся N. Результат принимается,
пока его sequence больше applied clock; поэтому N и затем N+1 могут примениться
по порядку, но запоздавший N после применённого N+1 отклоняется. Отклонение не
изменяет health, probe state, samples, events или failure-domain evidence.
Qualification резервирует выбранный batch одной транзакцией до отправки RPC.

Full probe при старте также сохраняет `failure_generation`. Применённый hard
failure от full или active увеличивает generation, поэтому начатый раньше full
result уже не может восстановить маршрут. Active success проверяет тот же
generation и не может отменить более новый hard failure. Обычный active result
изменяет только availability/recovery; score и service gates принадлежат full
qualification. Active hard failure атомарно меняет availability, probe state,
failure generation и, для VLESS, failure-domain evidence. Infrastructure
failure не создаёт hard-failure evidence и не увеличивает failure generation.

## Candidate lifecycle

Кандидаты проходят persisted lifecycle `active → draining → retired → delete`.
Успешный refresh переводит отсутствующие строки в `draining`, оставляет
зашифрованный payload и задаёт `drain_after` (по умолчанию через 15m).
Повторное появление того же stable ID до удаления возвращает его в `active`.
Qualification и новые назначения используют только active inventory; уже
сосланный assignment/plan может временно читать и наблюдать свой draining route,
пока controller безопасно его заменяет.

Maintenance collector обрабатывает не более 32 due-кандидатов за проход.
Переход в `retired`, а после `retired_retention` (по умолчанию 1m) физическое
удаление разрешены только при равных desired/applied generation, отсутствии
ссылок из assignments, working pool и обоих persisted plans, неизменном
`inventory_epoch` и подтверждённом Tor reconcile. Перед commit повторно
проверяются identity, generation, references, inventory epoch и semantic digest
Tor-набора; гонка даёт no-op, а уже выполненное удаление Tor компенсируется
повторным reconcile. Refresh, source update/delete и retirement увеличивают
`inventory_epoch`; публикация working pool фиксирует ожидаемый epoch и
отклоняется, если inventory успел измениться.

Удаление source также staged: source становится disabled/pending-delete, его
кандидаты — draining, а строка source удаляется только вместе с последним
безопасно собранным кандидатом. Lifecycle и clocks хранятся в SQLite, поэтому
restart controller не обходит grace, retention или reference fences.

## Adaptive tournament

Inventory и working pool разделены. Source refresh сохраняет до 10 000
уникальных кандидатов; превышение лимита отклоняет весь refresh и оставляет
last-known-good. Лимит 200 применяется только к working pool.

Очередь VLESS сначала выполняет дешёвый fast preflight, затем full probe для
прошедших кандидатов: 8 fast workers с deadline 6s и 4 full workers с deadline
20s. Приоритет: unseen, reset-expired, stale у границы, one-success, остальные,
текущий working pool. Состояние хранится по fingerprint и переживает повторный
import.

Tor discovery выполняет один последовательный worker, который один владеет
explorer-профилем на всём пути от его замены до readiness и измерения. Для Tor
действуют отдельные raw server deadlines: 5m для fast discovery и 6m для full
qualification; controller requests получают существующий response slack. VLESS
deadlines и число workers при этом не меняются, а explorer может принадлежать
только одному Tor discovery process. В отличие от VLESS, равный приоритет Tor
не сортируется по fingerprint: порядок текущей подписки остаётся tie-breaker.
Периодический runtime repair сравнивает только warm-профили и не удаляет
временный explorer во время qualification; после restart отсутствующий
сохранённый warm-пул восстанавливается reconcile.

- fast/full candidate failure увеличивает последовательный failure streak;
- третья ошибка переводит кандидата в ban;
- full success обнуляет failure streak;
- два full success дают eligibility;
- conservative score равен худшему из двух последних успешных full probe;
- через пять часов ban и streak сбрасываются, а старый score остаётся только
  stale-подсказкой;
- при заполненном pool challenger должен быть минимум на 15% лучше худшего
  рабочего кандидата.

Full probe проверяет Cloudflare/GStatic, YouTube, ChatGPT, OpenAI API, Telegram
Web, Telegram MTProto, Instagram и bounded speed download. Для VLESS UDP считается
пригодным только после двух свежих QUIC/TLS handshakes с YouTube через SOCKS5
UDP association; успешный DNS datagram сам по себе больше не квалифицирует
маршрут. YouTube gate требует успешный ответ от `https://www.youtube.com/generate_204`.
Instagram gate требует успешный ответ (<400) от `https://www.instagram.com/`. ChatGPT gate
принимает origin response без следования redirect: любой 2xx/3xx либо
аутентичные origin 403/429. OpenAI gate обращается именно к
`https://api.openai.com/v1/models` и принимает статусы 401, 204 или 200. Telegram требует и
доступность Web, и валидный MTProto-ответ.
Active probe использует приоритетные отдельные Xray slots, deadline 1900ms и
резерв ответа 75ms, поэтому background tournament не блокирует failover и сетевой
таймаут успевает вернуться как candidate hard-failure. Две независимые HTTP
проверки выполняются параллельно внутри одного цикла; второй внешний цикл для
hard failure не требуется. В том же active slot параллельно идёт дешёвая
routed-DNS проверка без bulk download, application gates и QUIC. Два соседних
DNS failure с успешным direct control подтверждают отказ маршрута.

## QoE control loop

QoE работает отдельным serial runtime-контуром и не занимает очередь
qualification или active liveness. Agent выделяет ему четыре отдельных Xray
slots и не более четырёх workers. VLESS измеряется через изолированный probe
outbound, Tor — через отдельный probe Tor-процесс того же кандидата с отдельными
SOCKS-портом и data directory; serving warm-профиль клиента не используется.
Explorer и замена serving warm-профиля для QoE не используются. Каждая probe загружает
ровно 65 536 байт с Cloudflare speed endpoint и имеет deadline 10s. Compression
и cache отключены, к query добавляется криптографически непредсказуемый nonce,
а тело читается только в bounded пределах.

Планирование выполняется на кандидата, а не на клиента:

- перед каждым QoE sweep обновляются WireGuard byte counters, чтобы новый трафик
  не ждал пятиминутного placement-цикла;
- назначенный маршрут с трафиком клиента за последние 2 минуты — с
  `qoe.active_interval` (15s в production);
- назначенный idle-маршрут — каждые 5m;
- `degraded` назначение — с более коротким из применимого active/idle и degraded
  интервалов;
- `degraded`, оставшийся без клиентов, — каждую 1m;
- до трёх qualified standby VLESS на каждый протокол и все reconciled
  unassigned warm Tor — каждые 15s до полного чистого окна, обязательного для
  quality-promotion.

TCP/UDP overlap дедуплицируется по candidate ID, а второй in-flight probe того
же кандидата coalesce. После завершения прохода следующий отсчитывается заново,
поэтому медленная probe не создаёт очередь просроченных ticks. Трафик одного
непрерывно active маршрута составляет примерно 360 МиБ/сутки, idle или одного
idle — 18 МиБ/сутки, promotion-standby — 360 МиБ/сутки, `degraded` recovery — до
90 МиБ/сутки. Число клиентов
на одном маршруте эти оценки не умножает.

Persisted state machine использует `learning`, `healthy`, `degraded`. Первые
пять успешных измерений устанавливают median baseline. До него severe sample —
TTFB >3s либо throughput <0,256 Мбит/с. После него sample плохой при candidate
connect/TLS/request/timeout/body failure, либо TTFB одновременно >1500ms и
>2,5x baseline, либо throughput <35% baseline. Infrastructure samples не входят
в окно. Три bad из последних пяти valid переводят маршрут в `degraded`, четыре
good из пяти восстанавливают. Параллельное availability-окно из 20 valid
samples деградирует маршрут после двух route/service failures, даже если они
разделены успешными проверками; recovery ждёт, пока этот счётчик опустится ниже
двух. Healthy baseline обновляется хорошими samples по
EWMA 0,1 и замораживается в `degraded`. История хранится 168h и удаляется
bounded batches; состояние и вызвавший его sample записываются одной SQLite
транзакцией.

Для VLESS QoE параллельно с TCP-измерением выполняет ту же реальную QUIC
проверку. Два последовательных провала снимают только `UDPQualified`, сохраняя
TCP score, availability и freshness; три последовательных успеха возвращают
UDP eligibility. Каждая смена немедленно запускает перепланирование UDP, но не
эвакуирует рабочий TCP и не переподключает WireGuard peer. Эта отдельная
гистерезисная петля предотвращает как назначение DNS-only UDP маршрута, так и
переключения из-за единичной потери QUIC-пакета.

Endpoint isolation отделяет деградацию маршрута от сбоя измерителя. Ошибочные
HTTP status, неожиданный размер и malformed response сразу считаются
infrastructure. После route transport/TLS/request error выполняется bounded
direct control: direct success подтверждает candidate failure. Параллельные
control requests объединяются в single-flight, а healthy result переиспользуется
30s. Если failed direct совпал с ошибками минимум трёх разных кандидатов в окне
30s, circuit открывается. Открытый circuit пропускает QoE-работу без изменения
окон и запускает не более одной direct recovery в минуту, пока endpoint не
восстановится. Service-specific active liveness при этом работает.

QoE migration разрешён только к normal-health available и полностью qualified
для нужного протокола кандидату в `healthy`. Его last valid sample должен быть
не старше 2m для active либо 10m для idle. Деградация TTFB/throughput считается
улучшением качества: median effective time `TTFB + 64 КиБ / throughput` должна
быть минимум на 30% лучше текущей, а переход проходит minimum dwell 30m,
подтверждение на трёх последовательных snapshots и общий planned-move limit. Единичная деградация
или колебание у границы сбрасывают streak.
Promotion дополнительно требует пять чистых active-cadence samples: последняя
точка не старше 40s, начало окна не старше 85s, максимальный разрыв между
соседними точками не более 25s. Старые или разреженные standby samples не
доказывают стабильность нового primary.

Единичный отказ application gates не меняет назначение. Подтверждённая QoE-окном
деградация с причиной `qoe_application_gates` означает недоступность клиентского
сервиса, а не просто снижение качества. Все клиенты этого маршрута сразу
переходят на полностью qualified альтернативу со свежим `healthy` QoE,
предпочитая цель со свежим active-proof, без speedup, dwell, snapshot streak,
planned-move limit и без
блокировки из-за неполного bounded reserve cover. Деградация TTFB/throughput
по-прежнему использует обычную гистерезисную политику.

Primary, reserve и emergency selection сначала сужают пригодный набор до
кандидатов со свежим `healthy` QoE. `learning` остаётся fallback только когда
такого stable-набора нет, поэтому отсутствие QoE capacity не превращается в
fail-closed, но высокий score недавно найденного маршрута не вытесняет
проверенный маршрут.

При `qoe.enabled: false` monitor, QoE placement trigger и QoE-фильтры scheduler
не создаются; qualification, hard-failure liveness и обычный balance остаются
Generic QoE никогда не заменяет service gates полного probe:
YouTube Web, Instagram, ChatGPT Web, допустимый ответ от OpenAI API (401, 204 или 200), Telegram Web и Telegram
MTProto всё равно обязательны для кандидата.
## Placement

Dataplane меняет только один serialized worker. Приоритет событий: hard failure,
подтверждённый `qoe_degraded`, manual reassign, lifecycle клиента,
promotion/demotion, periodic balance.
Повторяющиеся события coalesce. Scheduler использует weighted rendezvous;
неактивные аккаунты не занимают load. Healthy move требует 30% улучшения,
30-минутного dwell, трёх snapshots и свежего `healthy` QoE у целевого маршрута;
hard failure обходит эти ограничения. При отключённом QoE это дополнительное
ограничение не применяется.

Новый score-based quality move начинается только в periodic placement.
Promotion, capacity и другие служебные события могут немедленно чинить
недоступное назначение, но не создают дополнительные оптимизационные переносы
и не обходят лимит одного move.

Назначение sticky относительно клиента. Балансировка выбирает маршрут прежде
всего при первом назначении; добавление других клиентов и колебание нагрузки не
перемещают исправный existing assignment. Плановая миграция допускается лишь
при устойчивом улучшении минимум на 30% и ограничивается одним transport move
за цикл. Восстановившийся маршрут не забирает клиентов обратно автоматически.

При подтверждённом hard failure сначала используется уже материализованный
reserve. Если его active proof или runtime handler устарел, controller выбирает
лучший пригодный TCP-кандидат из общего Tor/VLESS-пула либо UDP-qualified VLESS,
добавляет его handler и меняет только затронутых клиентов. Transport становится
blocked лишь когда ни одного пригодного кандидата действительно нет; неполная
primary/reserve coverage сама по себе не создаёт blackout.

Применение выполняется add outbound → одна полная замена routing rules → remove
obsolete outbound, без промежуточного `block`. При неоднозначном результате
старый и новый handlers сохраняются, generation не подтверждается, а retry
идемпотентно повторяет финальные rules. Xray сохраняет уже принятые соединения
после смены rules; новые потоки идут через новый handler. Если сам старый egress
умер и публичный IP изменился, сохранить существующую TCP-сессию невозможно:
WireGuard остаётся поднятым, а приложение быстро создаёт новый TCP/QUIC flow.

TCP и UDP представлены независимо. TCP может использовать VLESS или warm Tor,
но Tor предоставляет только TCP. UDP разрешается лишь при наличии отдельно
квалифицированного VLESS-маршрута; иначе UDP остаётся заблокированным. Если
подходящего маршрута нет, блокируется только отсутствующий протокол. Правило
`.ru` direct располагается перед клиентскими proxy/block rules.

Для Tor зарезервированы три warm-профиля и один explorer. Первый мост, который
после fast success получает два успешных full probe, становится eligible,
переносится в warm-профиль и немедленно запускает placement. Остальные мосты
продолжают последовательную discovery в фоне, не занимая и не заменяя
warm-профили. При заполненном working pool общий promotion threshold сохраняется:
challenger должен быть минимум на 15% лучше худшего рабочего кандидата.

Расчётный профиль: 2 vCPU, 1 GiB RAM, до 50 WireGuard-клиентов и около 10
одновременно активных. VLESS probe-Xray имеет непересекающиеся ranges: 4 full,
8 fast, 4 active и 4 QoE slots.
