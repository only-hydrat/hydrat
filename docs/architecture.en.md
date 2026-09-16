<p align="center">
  <a href="architecture.md">Русский</a> · <strong>English</strong> · <a href="architecture.zh-CN.md">简体中文</a>
</p>

# Hydrat architecture

Hydrat consists of two Go processes running in separate network namespaces.

- `hydrat agent` owns WireGuard, nftables, main/probe Xray, Tor profiles, and all network-bound probes.
- `hydrat controller` owns sources, the adaptive tournament, scheduler, SQLite, and the administration UI.

The processes communicate over HTTP/JSON through a Unix socket. The portal is available inside WireGuard at `http://10.44.0.1:80`: the gateway redirects port 8080 to 80 with nftables and signs the real WireGuard IP with an internal token; the controller does not trust forged proxy headers. On the host, Compose publishes the portal only as `${PORTAL_BIND_ADDRESS:-127.0.0.1}:${PORTAL_PORT:-8088}:8080`. Use WireGuard or an authenticated HTTPS reverse proxy for external access, never a direct `0.0.0.0:8088` binding.

Client DNS and external DNS upstreams are separate. `wireguard.dns` publishes `10.44.0.1` in new client profiles, while `xray.dns_resolvers` defines a pool of public addresses (`1.1.1.1`, `9.9.9.9`, `8.8.8.8`); the singular `xray.dns_resolver` remains for compatibility. In the gateway namespace, a dedicated supervised dnsmasq serves this address. It sends requests to independent upstreams concurrently, caches responses, quickly retries lost requests, and can serve stale cache during a short upstream outage. DNS does not pass through the assigned client's stateful Xray handler and therefore does not freeze with an individual VLESS/XHTTP session. The trade-off is that DNS egress is direct from the gateway container, independently of the client's selected TCP/Tor route. Interception and configuration exist only in nftables/dnsmasq inside the gateway namespace; host and other-container DNS are untouched. No upstream may point back to the WireGuard gateway.

The QoE check for each TCP route still sends DNS-over-TCP to a deterministically selected upstream through that route's dedicated SOCKS proxy. On failure, direct control requests check the full pool concurrently: one reachable upstream proves user-visible route degradation, while failure of the entire pool does not reduce individual route scores.

Transparent policy routing in this namespace uses Hydrat-owned priority `10000`. A conflicting foreign rule at that priority stops bootstrap without deleting or modifying the foreign rule.

The agent persists the applied plan. After restart it waits for Xray, performs add → route for the stored generation, and only then becomes ready. A gateway restart therefore does not require a controller restart, and a controller restart does not remove already applied routes.

TCP and UDP assignments are independent. When a UDP-qualified VLESS route is available, the scheduler attempts to co-assign it for both protocols. TCP may use VLESS or a warmed single-bridge Tor profile; UDP uses only qualified VLESS. During emergency replacement, Tor participates in the common TCP pool with VLESS and can become the replacement according to failure domain, load, and score. Normal primary placement still prefers VLESS.

Recognized `.ru`, `.su`, and `.xn--p1ai` domains and addresses in `direct_domains` go directly. When `routing.geo_rules.enabled: true`, GeoRules uses periodically refreshed GeoSite and GeoIP databases (`russia-blocked-geosite` and `russia-blocked-geoip`, every 24 hours by default): `geosite:category-ru` and `geoip:ru` go to `direct`, while `geosite:russia-blocked` and `geoip:russia-blocked` are forced through a proxy. During pre-probe filtering, `routing.disallow_ru_egress: true` excludes egress nodes in Russia; the setting is persisted in configuration and `routing.json`. Unknown traffic remains proxied and fails closed when no eligible route exists. IPv6, NaiveProxy, onion routing, and automatic core updates are not supported.

Sources are managed in the administration portal. Mixed-input preview accepts VLESS links, VLESS subscription URLs, Tor bridge lines, and bridge-list URLs. `obfs4` and `webtunnel` bridges may omit the optional `Bridge` prefix; the parser stores them canonically as `Bridge <original line>`. Unknown transports, invalid addresses, and invalid fingerprints remain invalid.

Sensitive payload fields are encrypted with AES-GCM before they are stored in SQLite. This is not full SQLite encryption and does not protect against host-root compromise. Existing routes keep working during refresh, and a refresh error preserves the last-known-good candidate inventory.

Internal `source_position` is zero-based. Migration version 3 gives existing candidates a fallback order of `created_at, id`; a successful refresh transactionally replaces it with current subscription order. The controller consumes store order without sorting Tor candidates by fingerprint. Tor queue priority is inventory-generation aware: current unseen candidates run before retries, and `source_position` breaks ties at the same priority. A candidate removed by a concurrent refresh is skipped without stopping the loop; the next loop uses the new inventory and schedules new unseen candidates before retries.

## Causal observation state

Fast, full, and active probes have independent persisted clocks. Before a network RPC, the controller reserves a stage-specific sequence: `*_result_seq` is the allocated clock and `*_applied_seq` is the last atomically applied result. Reserving N+1 does not cancel an in-flight N. A result is accepted while its sequence is greater than the applied clock, so N followed by N+1 can apply in order, but a late N after N+1 is rejected. Rejection does not change health, probe state, samples, events, or failure-domain evidence. Qualification reserves the selected batch in one transaction before sending RPCs.

A full probe also stores `failure_generation` when it starts. An applied hard failure from a full or active probe increments the generation, preventing an older full result from restoring the route. Active success checks the same generation and cannot override a newer hard failure. A normal active result changes only availability and recovery; score and service gates belong to full qualification. An active hard failure atomically changes availability, probe state, failure generation, and, for VLESS, failure-domain evidence. Infrastructure failures do not create hard-failure evidence or increment the generation.

## Candidate lifecycle

Candidates follow the persisted lifecycle `active → draining → retired → delete`. A successful refresh moves missing entries to `draining`, retains the encrypted payload, and sets `drain_after` to 15 minutes by default. Reappearance of the same stable ID before deletion returns it to `active`. Qualification and new assignments use only active inventory; an existing assignment or plan may temporarily read and observe its draining route while the controller replaces it safely.

The maintenance collector processes at most 32 due candidates per pass. Moving to `retired`, and physical deletion after `retired_retention` (one minute by default), is allowed only when desired and applied generations match, assignments, the working pool, and both persisted plans contain no references, `inventory_epoch` is unchanged, and Tor reconciliation is acknowledged. Identity, generation, references, inventory epoch, and the semantic digest of the Tor set are checked again before commit. A race becomes a no-op; an already performed Tor deletion is compensated by another reconciliation. Refresh, source update/delete, and retirement increment `inventory_epoch`; publishing the working pool records the expected epoch and is rejected if inventory changed.

Source deletion is also staged: the source becomes disabled and pending deletion, its candidates enter draining, and the source row is removed only with its last safely collected candidate. Lifecycle and clocks are stored in SQLite, so a controller restart cannot bypass grace, retention, or reference fences.

## Adaptive tournament

Inventory and working pool are separate. Source refresh stores up to 10,000 unique candidates. Exceeding the limit rejects the entire refresh and retains the last-known-good inventory. The 200-candidate limit applies only to the working pool.

The VLESS queue runs a cheap fast preflight and then a full probe for candidates that pass: eight fast workers with a 6-second deadline and four full workers with a 20-second deadline. Priority is unseen, reset-expired, stale near the boundary, one-success, remaining candidates, then the current working pool. State is stored by fingerprint and survives repeated imports.

Tor discovery uses one serial worker that exclusively owns the explorer profile from replacement through readiness and measurement. Tor has separate raw server deadlines: five minutes for fast discovery and six minutes for full qualification; controller requests retain the existing response slack. VLESS deadlines and worker counts do not change, and only one Tor discovery process may own the explorer. Unlike VLESS, equal-priority Tor candidates are not sorted by fingerprint: current subscription order remains the tie-breaker. Periodic runtime repair compares only warm profiles and does not remove the temporary explorer during qualification; after restart, a missing stored warm pool is restored by reconciliation.

- Fast or full candidate failure increments the consecutive failure streak.
- The third failure bans the candidate.
- Full success resets the failure streak.
- Two full successes grant eligibility.
- Conservative score is the worse of the latest two successful full probes.
- After five hours, ban and streak reset; the old score remains only as a stale hint.
- When the pool is full, a challenger must be at least 15% better than the worst working candidate.

Full probes check Cloudflare/GStatic, YouTube, ChatGPT, the OpenAI API, Telegram Web, Telegram MTProto, Instagram, and a bounded speed download. VLESS becomes UDP-eligible only after two fresh QUIC/TLS handshakes with YouTube over a SOCKS5 UDP association; a successful DNS datagram alone no longer qualifies a route. The YouTube gate requires a successful response from `https://www.youtube.com/generate_204`. The Instagram gate requires a response below 400 from `https://www.instagram.com/`. The ChatGPT gate accepts the origin response without following redirects: any 2xx/3xx or authentic origin 403/429. The OpenAI gate calls `https://api.openai.com/v1/models` and accepts 401, 204, or 200. Telegram requires both Web availability and a valid MTProto response.

Active probes use separate priority Xray slots, a 1900 ms deadline, and 75 ms response slack. The background tournament therefore cannot block failover, and a network timeout returns in time as a candidate hard failure. Two independent HTTP checks run concurrently within one cycle; a second outer cycle is not required. A cheap routed-DNS check runs concurrently in the same active slot without bulk download, application gates, or QUIC. Two adjacent DNS failures with a successful direct control confirm route failure.

## QoE control loop

QoE runs in a separate serial runtime loop and does not occupy qualification or active-liveness queues. The agent reserves four Xray slots and at most four workers for it. VLESS is measured through an isolated probe outbound. Tor uses a separate probe process for the same candidate with its own SOCKS port and data directory; the client's serving warm profile is never used. QoE does not use the explorer or replace a serving warm profile. Each probe downloads exactly 65,536 bytes from the Cloudflare speed endpoint with a 10-second deadline. Compression and cache are disabled, a cryptographically unpredictable nonce is added to the query, and the body is read only within fixed bounds.

Scheduling operates per candidate, not per client:

- Before each QoE sweep, WireGuard byte counters are refreshed so new traffic does not wait for the five-minute placement cycle.
- An assigned route with client traffic in the last two minutes uses `qoe.active_interval` (15 seconds in production).
- An assigned idle route runs every five minutes.
- A `degraded` assignment uses the shorter applicable active/idle or degraded interval.
- A `degraded` route with no clients runs every minute.
- Up to three qualified standby VLESS routes per protocol and all reconciled unassigned warm Tor routes run every 15 seconds until they build the full clean window required for quality promotion.

TCP/UDP overlap is deduplicated by candidate ID, and a second in-flight probe for the same candidate is coalesced. The next pass is scheduled after completion, so a slow probe cannot create a queue of expired ticks. One continuously active route uses about 360 MiB/day, an idle route about 18 MiB/day, a promotion standby about 360 MiB/day, and `degraded` recovery up to 90 MiB/day. More clients on the same route do not multiply these figures.

The persisted state machine uses `learning`, `healthy`, and `degraded`. The first five successful measurements establish a median baseline. Before that, a severe sample is TTFB above 3 seconds or throughput below 0.256 Mbit/s. Afterward, a sample is bad on candidate connection/TLS/request/timeout/body failure, or when TTFB is both above 1500 ms and above 2.5 times baseline, or throughput is below 35% of baseline. Infrastructure samples do not enter the window. Three bad samples among the latest five valid samples enter `degraded`; four good samples among five recover. A parallel availability window of 20 valid samples degrades the route after two route/service failures even when separated by successes; recovery waits until the count drops below two. Good samples update a healthy baseline with EWMA 0.1; the baseline freezes in `degraded`. History is retained for 168 hours and deleted in bounded batches. State and the triggering sample are written in one SQLite transaction.

For VLESS, QoE runs the same real QUIC check concurrently with the TCP measurement. Two consecutive failures remove only `UDPQualified`, retaining TCP score, availability, and freshness; three consecutive successes restore UDP eligibility. Every transition triggers immediate UDP replanning without evacuating working TCP or reconnecting the WireGuard peer. This separate hysteresis loop prevents both DNS-only UDP routes and switches caused by a single lost QUIC packet.

Endpoint isolation distinguishes route degradation from measurement failure. Invalid HTTP status, unexpected size, and malformed response are immediately classified as infrastructure. After a route transport/TLS/request error, bounded direct control runs: direct success confirms candidate failure. Concurrent control requests are single-flighted and a healthy result is reused for 30 seconds. If failed direct control coincides with errors from at least three distinct candidates in 30 seconds, the circuit opens. An open circuit skips QoE work without changing windows and starts at most one direct recovery per minute until the endpoint recovers. Service-specific active liveness continues to run.

QoE migration is allowed only to a normal-health, available candidate that is fully qualified for the required protocol and in `healthy` state. Its last valid sample must be no older than two minutes for active traffic or ten minutes for idle traffic. TTFB/throughput degradation uses quality-improvement migration: median effective time `TTFB + 64 KiB / throughput` must be at least 30% better than the current route, with a 30-minute minimum dwell, confirmation across three consecutive snapshots, and the common planned-move limit. A single degraded sample or boundary oscillation resets the streak.

Promotion additionally requires five clean active-cadence samples: the last point no older than 40 seconds, the window start no older than 85 seconds, and no gap above 25 seconds. Old or sparse standby samples do not prove stability of a new primary.

A single application-gate failure does not change placement. QoE-window-confirmed degradation with reason `qoe_application_gates` means a client service is unavailable, not merely slower. All clients on that route immediately move to a fully qualified alternative with fresh `healthy` QoE, preferring a target with fresh active proof. This bypasses speedup, dwell, snapshot streak, planned-move limit, and incomplete bounded-reserve-cover blocking. TTFB/throughput degradation still uses the normal hysteresis policy.

Primary, reserve, and emergency selection first narrow eligible candidates to those with fresh `healthy` QoE. `learning` is a fallback only when no stable set exists. Missing QoE capacity therefore does not cause fail-closed, while a newly discovered high-score route cannot displace a proven route.

When `qoe.enabled: false`, the monitor, QoE placement trigger, and scheduler QoE filters are not created; qualification, hard-failure liveness, and normal balancing remain active. Generic QoE never replaces full-probe service gates: YouTube Web, Instagram, ChatGPT Web, an acceptable OpenAI API response (401, 204, or 200), Telegram Web, and Telegram MTProto remain mandatory.

## Placement

Only one serialized worker changes the dataplane. Event priority is hard failure, confirmed `qoe_degraded`, manual reassignment, client lifecycle, promotion/demotion, then periodic balance. Repeated events coalesce. The scheduler uses weighted rendezvous; inactive accounts do not consume load. A healthy move requires a 30% improvement, 30-minute dwell, three snapshots, and fresh `healthy` QoE on the target. Hard failure bypasses these restrictions. The extra QoE constraint is absent when QoE is disabled.

A new score-based quality move begins only during periodic placement. Promotion, capacity, and other service events may immediately repair an unavailable assignment, but they do not create extra optimization moves or bypass the one-move limit.

Assignments are sticky per client. Balancing chooses a route primarily during initial assignment; adding clients and load fluctuations do not move a healthy existing assignment. Planned migration requires a stable improvement of at least 30% and is limited to one transport move per cycle. A recovered route does not automatically take clients back.

After a confirmed hard failure, the controller first uses the materialized reserve. If its active proof or runtime handler is stale, the controller selects the best eligible TCP candidate from the common Tor/VLESS pool or a UDP-qualified VLESS candidate, adds its handler, and changes only affected clients. A transport becomes blocked only when no eligible candidate actually exists; incomplete primary/reserve coverage alone does not cause a blackout.

Normal TCP primary placement prefers eligible VLESS. For a VLESS primary, the reserve prefers VLESS from a separate failure domain but may use warm Tor if it is the only failure-domain-safe reserve. Emergency replacement treats eligible warm VLESS and Tor routes equally and selects by failure domain, load, and score; Tor is not delayed until every VLESS route fails. UDP remains VLESS-only.

Application follows add outbound → one complete routing-rule replacement → remove obsolete outbound, with no intermediate `block`. After an ambiguous result, old and new handlers are retained, the generation is not acknowledged, and retry idempotently repeats the final rules. Xray keeps already accepted connections after rule replacement; new flows use the new handler. If the old egress itself is dead and the public IP changes, an existing TCP session cannot be preserved: WireGuard remains up and the application creates a new TCP/QUIC flow.

TCP and UDP are represented independently. TCP may use VLESS or warm Tor, but Tor provides TCP only. UDP is allowed only with a separately qualified VLESS route; otherwise UDP remains blocked. If no suitable route exists, only the missing protocol is blocked. The `.ru` direct rule precedes client proxy/block rules.

Tor reserves three warm profiles and one explorer. The first bridge that receives two successful full probes after fast success becomes eligible, moves into a warm profile, and immediately triggers placement. Other bridges continue serial discovery in the background without consuming or replacing warm profiles. When the working pool is full, the common promotion threshold remains: a challenger must be at least 15% better than the worst working candidate.

Sizing target: 2 vCPU, 1 GiB RAM, up to 50 WireGuard clients, and about 10 simultaneously active clients. VLESS probe Xray uses non-overlapping ranges: four full, eight fast, four active, and four QoE slots.
