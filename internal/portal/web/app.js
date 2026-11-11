const $ = (id) => document.getElementById(id);
let adminToken = "";
let candidateOffset = 0;
let artifactConfig = "";
let artifactName = "wireguard";

function notify(message, error = false) {
  const toast = $("message");
  toast.textContent = message;
  toast.className = `toast show${error ? " error" : ""}`;
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => { toast.className = "toast"; }, 3500);
}

async function request(url, options = {}, admin = false, raw = false) {
  const headers = new Headers(options.headers || {});
  if (admin) headers.set("Authorization", `Bearer ${adminToken}`);
  if (options.body && typeof options.body !== "string") {
    headers.set("Content-Type", "application/json");
    options.body = JSON.stringify(options.body);
  }
  const response = await fetch(url, {...options, headers});
  if (response.status === 401 && (admin || url === "/api/admin/session")) clearAdminSession();
  if (raw && response.ok) return response;
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function clearAdminSession() {
  adminToken = "";
  $("admin-password").value = "";
  $("admin-logout").hidden = true;
  history.replaceState(null, "", "#overview");
  // Reload discards all admin projections, dialogs, cached artifacts and Blob URLs.
  location.reload();
}

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

function button(text, action, kind = "ghost") {
  const item = node("button", `button ${kind}`, text);
  item.type = "button";
  item.addEventListener("click", action);
  return item;
}

function setView(name) {
  const showOnionGuide = name === "onion" || name === "system-onion";
  const showI2PGuide = name === "system-i2p";
  if (showOnionGuide || showI2PGuide) name = "system";
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.dataset.view === name));
  document.querySelectorAll("[data-nav]").forEach((item) => item.classList.toggle("active", item.dataset.nav === name));
  $("page-title").textContent = {overview:"Обзор",clients:"Клиенты",sources:"Источники",candidates:"Кандидаты",system:"Система"}[name];
  history.replaceState(null, "", `#${showOnionGuide ? "system-onion" : showI2PGuide ? "system-i2p" : name}`);
  if (showOnionGuide) {
    $("onion-guide").open = true;
    $("onion-guide").scrollIntoView?.({block:"start"});
  }
  if (showI2PGuide) {
    $("i2p-settings").open = true;
    $("i2p-settings").scrollIntoView?.({block:"start"});
  }
  if (adminToken) {
    if (name === "candidates") loadCandidates(true);
    if (name === "system") loadSystem();
  }
}

document.querySelectorAll("[data-nav]").forEach((item) => item.addEventListener("click", () => setView(item.dataset.nav)));

async function loadSelf() {
  try {
    const data = await request("/api/me");
    const formatRoute = (kind, label, id) => {
      if (!id || id === "block") return "заблокирован";
      const displayKind = kind ? (kind === "tor_bridge" ? "tor" : kind) : "";
      if (label) return displayKind ? `${displayKind} · ${label}` : label;
      return id;
    };
    const tcp = formatRoute(data.tcp_kind, data.tcp_label, data.tcp_assignment);
    const udp = formatRoute(data.udp_kind, data.udp_label, data.udp_assignment);
    const presence = data.connection_state === "inactive" ? "Неактивен — резервация освобождена" : data.connection_state === "unavailable" ? "Нет доступного маршрута" : data.paused ? "Пауза" : "В сети";
    const identity = node("div", "connection-identity");
    identity.append(node("strong", "", data.name), node("span", "", presence));
    const routes = node("dl", "connection-routes");
    [["TCP", tcp], ["UDP", udp], [".onion", onionStatusText(data.onion_status)], [".i2p", i2pPermissionText(data.i2p_status)]].forEach(([label, value]) => {
      const item = node("div");
      item.append(node("dt", "", label), node("dd", "", value));
      routes.append(item);
    });
    $("status").replaceChildren(identity, routes);
  } catch (error) {
    $("status").textContent = "Откройте панель через WireGuard\n" + error.message;
  }
}

$("reassign").addEventListener("click", async () => {
  try {
    await request("/api/me/reassign", {method:"POST", headers:{"X-Hydrat-Action":"reassign"}});
    notify("Переназначение поставлено в приоритетную очередь");
    setTimeout(loadSelf, 1200);
  } catch (error) { notify(error.message, true); }
});

$("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const data = await request("/api/admin/session", {method:"POST", headers:{"X-Hydrat-Admin-Password":$("admin-password").value}});
    adminToken = data.token;
    $("admin-logout").hidden = false;
  } catch (error) { notify(error.message, true); return; }
  finally {
    $("admin-password").value = "";
  }
  try {
    await Promise.all([loadOverview(), loadClients(), loadSources(), loadSystem()]);
    notify("Админ-панель подключена");
  } catch (error) { notify(error.message, true); }
});

$("admin-logout").addEventListener("click", async () => {
  try {
    await request("/api/admin/session", {method:"DELETE"}, true);
  } catch (error) { notify(error.message, true); }
  finally {
    clearAdminSession();
  }
});

async function loadOverview() {
  const data = await request("/api/admin/system", {}, true);
  const working = data.working_pool_by_kind || {};
  const capacity = data.effective_capacity || {};
  document.querySelector('[data-stat="vless-working"]').textContent = working.vless || 0;
  document.querySelector('[data-stat="vless-domains"]').textContent = capacity.vless_failure_domains || 0;
  document.querySelector('[data-stat="tor-candidates"]').textContent = working.tor_bridge || 0;
  document.querySelector('[data-stat="tor-warm"]').textContent = capacity.tor_warm_profiles || 0;
  const target = $("status-breakdown");
  target.replaceChildren();
  target.className = "status-grid";
  const statuses = data.candidate_statuses || {};
  if (!Object.keys(statuses).length) {
    target.className = "status-grid empty";
    target.textContent = "Кандидаты ещё не проверены";
  } else {
    Object.entries(statuses).sort().forEach(([name, count]) => {
      const chip = node("div", "status-chip");
      chip.append(node("span", "cell-label", name), node("strong", "", count));
      target.append(chip);
    });
  }
}

async function loadClients() {
  const data = await request("/api/admin/clients", {}, true);
  const assignments = new Map((data.assignments || []).map((item) => [item.client_id, item]));
  const target = $("admin-clients");
  target.replaceChildren();
  target.className = "data-list";
  if (!(data.clients || []).length) {
    target.className = "data-list empty";
    target.textContent = "Создайте первый WireGuard-клиент";
    return;
  }
  data.clients.forEach((client) => {
    const assignment = assignments.get(client.id) || {};
    const row = node("article", "data-row");
    const identity = node("div");
    identity.append(node("strong", "", client.name), node("small", "", client.address));
    const inactive = client.connection_state === "inactive";
    const state = client.paused ? "Пауза" : inactive ? "Неактивен — резервация освобождена" : client.connection_state === "unavailable" ? "Нет доступного маршрута" : "В сети";
    row.append(identity, metric(inactive ? "Общий TCP" : "TCP", assignment.tcp_outbound || "block"), metric(inactive ? "Общий UDP" : "UDP", assignment.udp_outbound || "block"), badge(state, client.paused || inactive ? "neutral" : client.connection_state === "unavailable" ? "bad" : "good"));
    const actions = node("div", "actions");
    actions.append(
      button("Конфиг / QR", () => showArtifacts(client)),
      button(client.paused ? "Возобновить" : "Пауза", () => toggleClient(client)),
      button("Другой маршрут", () => reassignClient(client)),
      button("Переименовать", () => renameClient(client)),
      button(client.i2p_enabled ? "Выключить .i2p" : "Доступ к .i2p", () => toggleI2P(client)),
      button(client.onion_enabled ? "Выключить .onion" : "Доступ к .onion через Tor", () => toggleOnion(client)),
      button("Удалить", () => deleteClient(client), "danger")
    );
    identity.append(node("small", "", `.i2p: ${i2pPermissionText(client.i2p_status)}`));
    identity.append(node("small", "", `.onion: ${onionStatusText(client.onion_status)}`));
    row.append(actions);
    target.append(row);
  });
}

function metric(label, value) {
  const cell = node("div");
  cell.append(node("span", "cell-label", label), node("strong", "", short(value)));
  cell.title = value;
  return cell;
}

function badge(text, style) { return node("span", `badge ${style}`, text); }
function short(value) { return value && value.length > 18 ? `${value.slice(0, 9)}…${value.slice(-6)}` : value; }

$("client-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const client = await request("/api/admin/clients", {method:"POST", body:{name:$("client-name").value}}, true);
    $("client-name").value = "";
    await loadClients();
    await showArtifacts(client);
    notify("Клиент создан");
  } catch (error) { notify(error.message, true); }
});

async function showArtifacts(client) {
  try {
    const [configData, qrResponse] = await Promise.all([
      request(`/api/admin/clients/${encodeURIComponent(client.id)}/config.json`, {}, true),
      request(`/api/admin/clients/${encodeURIComponent(client.id)}/qr.png`, {}, true, true)
    ]);
    artifactConfig = configData.config;
    artifactName = client.name || "wireguard";
    $("artifact-title").textContent = artifactName;
    $("artifact-config").textContent = artifactConfig;
    $("artifact-qr").src = URL.createObjectURL(await qrResponse.blob());
    $("artifact-dialog").showModal();
  } catch (error) { notify(error.message, true); }
}

async function toggleClient(client) {
  try {
    await request(`/api/admin/clients/${encodeURIComponent(client.id)}/${client.paused ? "resume" : "pause"}`, {method:"POST"}, true);
    await loadClients();
  } catch (error) { notify(error.message, true); }
}
async function reassignClient(client) {
  try {
    await request(`/api/admin/clients/${encodeURIComponent(client.id)}/reassign`, {method:"POST"}, true);
    notify("Переназначение запланировано");
  } catch (error) { notify(error.message, true); }
}
async function renameClient(client) {
  const name = prompt("Новое имя клиента", client.name);
  if (!name || name === client.name) return;
  try {
    await request(`/api/admin/clients/${encodeURIComponent(client.id)}/rename`, {method:"POST", body:{name}}, true);
    await loadClients();
  } catch (error) { notify(error.message, true); }
}
async function deleteClient(client) {
  if (!confirm(`Удалить ${client.name}? WireGuard-конфиг перестанет работать.`)) return;
  try {
    await request(`/api/admin/clients/${encodeURIComponent(client.id)}`, {method:"DELETE"}, true);
    await loadClients();
    await loadOverview();
  } catch (error) { notify(error.message, true); }
}

$("artifact-close").addEventListener("click", () => $("artifact-dialog").close());
$("artifact-copy").addEventListener("click", async () => { await navigator.clipboard.writeText(artifactConfig); notify("Конфиг скопирован"); });
$("artifact-download").addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([artifactConfig], {type:"text/plain"}));
  link.download = `${artifactName.replace(/[^a-z0-9_-]+/gi, "-")}.conf`;
  link.click();
  URL.revokeObjectURL(link.href);
});

async function loadSources() {
  const data = await request("/api/admin/sources", {}, true);
  const target = $("admin-sources");
  target.replaceChildren();
  target.className = "data-list";
  const sources = (data.sources || []).filter((source) => !source.pending_delete);
  if (!sources.length) {
    target.className = "data-list empty";
    target.textContent = "Источников пока нет";
    return;
  }
  sources.forEach((source) => {
    const row = node("article", "data-row");
    const identity = node("div");
    identity.append(node("strong", "", source.label), node("small", "", source.kind));
    row.append(identity, metric("Кандидаты", String(source.candidate_count || 0)), metric("Ошибка", source.last_refresh_error || "нет"), badge(source.enabled ? "Включён" : "Выключен", source.enabled ? "good" : "warn"));
    const actions = node("div", "actions");
    actions.append(button("Обновить", () => refreshSource(source)), button(source.enabled ? "Отключить" : "Включить", () => toggleSource(source)), button("Удалить", () => deleteSource(source), "danger"));
    row.append(actions);
    target.append(row);
  });
}

$("source-preview").addEventListener("click", async () => {
  try {
    const result = await request("/api/admin/sources/preview", {method:"POST", body:{input:$("source-input").value}}, true);
    $("source-result").textContent = JSON.stringify(result, null, 2);
  } catch (error) { $("source-result").textContent = error.message; }
});
$("source-import").addEventListener("click", async () => {
  try {
    const result = await request("/api/admin/sources/import", {method:"POST", body:{input:$("source-input").value}}, true);
    $("source-result").textContent = JSON.stringify(result, null, 2);
    await Promise.all([loadSources(), loadOverview()]);
  } catch (error) { notify(error.message, true); }
});
async function refreshSource(source) {
  try { notify("Источник обновляется…"); await request(`/api/admin/sources/${source.id}/refresh`, {method:"POST"}, true); await loadSources(); notify("Источник обновлён"); }
  catch (error) { notify(error.message, true); }
}
async function toggleSource(source) {
  try { await request(`/api/admin/sources/${source.id}`, {method:"PATCH", body:{label:source.label,enabled:!source.enabled}}, true); await loadSources(); }
  catch (error) { notify(error.message, true); }
}
async function deleteSource(source) {
  if (!confirm(`Удалить источник ${source.label}?`)) return;
  try { await request(`/api/admin/sources/${source.id}`, {method:"DELETE"}, true); await Promise.all([loadSources(), loadOverview()]); }
  catch (error) { notify(error.message, true); }
}

async function loadCandidates(reset = false) {
  if (reset) candidateOffset = 0;
  const params = new URLSearchParams({limit:"100",offset:String(candidateOffset)});
  if ($("candidate-filter").value) params.set("status", $("candidate-filter").value);
  if ($("candidate-kind").value) params.set("kind", $("candidate-kind").value);
  if ($("candidate-search").value) params.set("q", $("candidate-search").value);
  try {
    const data = await request(`/api/admin/candidates?${params}`, {}, true);
    const target = $("admin-candidates");
    if (reset) target.replaceChildren();
    target.className = "data-list";
    (data.candidates || []).forEach((candidate) => {
      const state = candidate.state || {};
      const health = candidate.health || {};
      const qoe = candidate.qoe || {};
      const qoeText = qoe.status || "learning";
      const speed = qoe.throughput_mbps > 0 ? `${qoe.throughput_mbps.toFixed(2)} Mbit/s` : "—";
      const ttfb = qoe.ttfb_ms > 0 ? `${Math.round(qoe.ttfb_ms)} ms` : "—";
      const row = node("article", "data-row");
      const identity = node("div");
      identity.append(node("strong", "", candidate.label), node("small", "", `${candidate.kind} · ${candidate.fingerprint}`));
      row.append(identity, metric("Score", health.score === undefined ? "—" : health.score.toFixed(1)), metric("Streak", `${state.full_success_streak || 0} ✓ / ${state.failure_streak || 0} ✕`), badge(state.status || "unknown", state.status === "qualified" ? "good" : state.status === "banned" ? "bad" : "neutral"));
      const info = node("div", "actions candidate-meta");
      info.append(
        badge(`QoE ${qoeText}`, qoeText === "healthy" ? "good" : qoeText === "degraded" ? "bad" : "warn"),
        node("span", "cell-label", `TTFB ${ttfb} · ${speed}`),
        node("span", "cell-label", state.in_working_pool ? "WORKING POOL" : state.draining ? "DRAINING" : health.available ? "AVAILABLE" : "")
      );
      const reasons = {policy_ru_egress:"Исключён политикой RU-egress",never_attempted:"Ожидает первой проверки",infrastructure_error:"Ошибка проверяющей инфраструктуры",candidate_failed:"Ошибка маршрута",awaiting_qualification:"Ожидает квалификации",qualified:"Квалифицирован"};
      info.append(node("span", "cell-label", reasons[candidate.selection_reason] || candidate.selection_reason || ""));
      if (candidate.last_probe_at) info.append(node("span", "cell-label", `Последняя проверка: ${new Date(candidate.last_probe_at).toLocaleString()}`));
      row.append(info);
      target.append(row);
    });
    if (!target.children.length) { target.className = "data-list empty"; target.textContent = "Ничего не найдено"; }
    candidateOffset += (data.candidates || []).length;
    $("candidate-total").textContent = `${data.total} кандидатов`;
    $("candidate-more").disabled = candidateOffset >= data.total;
  } catch (error) { notify(error.message, true); }
}
["candidate-filter","candidate-kind"].forEach((id) => $(id).addEventListener("change", () => loadCandidates(true)));
$("candidate-search").addEventListener("input", () => { clearTimeout(loadCandidates.timer); loadCandidates.timer = setTimeout(() => loadCandidates(true), 250); });
$("candidate-more").addEventListener("click", () => loadCandidates(false));

async function loadSystem() {
  const [system, profiles] = await Promise.all([
    request("/api/admin/system", {}, true),
    request("/api/admin/profiles", {}, true)
  ]);
  const details = $("system-details");
  details.replaceChildren();
  const qoeStatuses = system.qoe_statuses || {};
  const qoeSummary = `learning ${qoeStatuses.learning || 0} · healthy ${qoeStatuses.healthy || 0} · degraded ${qoeStatuses.degraded || 0}`;
  const working = system.working_pool_by_kind || {};
  const capacity = system.effective_capacity || {};
  const runtime = system.probe_runtime || {};
  const activeRuntime = system.active_probe_runtime || {};
  const coverage = system.probe_coverage || {};
  const probeActivity = system.probe_activity_5h || {};
  const summarizeRuntime = (value) => {
    const rssMiB = Number.isFinite(value.rss_bytes) ? (value.rss_bytes / 1048576).toFixed(1) : "—";
    return `${value.status || "unavailable"} · epoch ${value.epoch || 0} · RSS ${rssMiB} MiB · FDs ${value.fd_count || 0} · probes ${value.completed_probes || 0} · recycles ${value.recycle_count || 0}${value.last_recycle_reason ? ` · ${value.last_recycle_reason}` : ""}`;
  };
  [
    ["Шлюз/API",system.health_status || "неизвестно"],
    ["Готовность маршрутизации",system.readiness_status || "неизвестно"],
    ["Источники",system.source_count],
    ["Кандидаты",system.candidate_count],
    ["Ожидают первой проверки",coverage.never_attempted || 0],
    ["Исключены политикой",coverage.excluded_policy || 0],
    ["Ошибки инфраструктуры",coverage.infrastructure_error || 0],
    ["Ошибки маршрутов",coverage.candidate_failed || 0],
    ["Охват полных проверок за 5 ч",`${probeActivity.distinct_candidates || 0} кандидатов / ${probeActivity.full_probes || 0} проверок`],
    ["VLESS working",working.vless || 0],
    ["VLESS domains",capacity.vless_failure_domains || 0],
    ["Tor candidates",working.tor_bridge || 0],
    ["Warm Tor",capacity.tor_warm_profiles || 0],
    ["Draining",system.draining_count],
    ["QoE",qoeSummary],
    ["Probe runtime",summarizeRuntime(runtime)],
    ["Active runtime",summarizeRuntime(activeRuntime)],
    ["Desired generation",system.desired_generation],
    ["Applied generation",system.applied_generation]
  ].forEach(([key,value]) => details.append(node("dt","",key),node("dd",key.endsWith("runtime") ? "probe-runtime" : "",String(value))));
  const target = $("admin-profiles");
  target.replaceChildren();
  target.className = "data-list";
  (profiles.profiles || []).forEach((profile) => {
    const row = node("article","data-row");
    row.append(metric(profile.role, profile.candidate_id), metric("SOCKS", profile.socks_addr), metric("Слот", String(profile.slot)), badge("Запущен","good"));
    target.append(row);
  });
  if (!target.children.length) { target.className = "data-list empty"; target.textContent = "Tor-профили не запущены"; }
  await loadRouting();
}
$("profile-explore").addEventListener("click", async () => {
  try { await request("/api/admin/profiles/explore", {method:"POST"}, true); await loadSystem(); }
  catch (error) { notify(error.message, true); }
});

let currentRoutingState = null;

async function loadRouting() {
  try {
    const data = await request("/api/admin/routing", {}, true);
    currentRoutingState = data;
    renderRouting(data);
  } catch (error) {
    console.error("load routing failed", error);
  }
}

function renderRouting(data) {
  if (!data) return;
  const suffixes = (data.direct_suffixes || []).join(", ") || "—";
  const domains = (data.direct_domains || []).join(", ") || "—";
  $("routing-suffixes").textContent = suffixes;
  $("routing-domains").textContent = domains;

  const geoStatus = data.geo_status || {};
  const geoRules = data.geo_rules || {};

  const formatSize = (bytes) => {
    if (!bytes || bytes <= 0) return "—";
    return (bytes / (1024 * 1024)).toFixed(1) + " МБ";
  };

  const formatDate = (iso) => {
    if (!iso || iso === "0001-01-01T00:00:00Z") return "—";
    try {
      const d = new Date(iso);
      return d.toLocaleString("ru-RU");
    } catch {
      return String(iso);
    }
  };

  const geoipText = geoStatus.geoip_exists
    ? `Загружен (${formatSize(geoStatus.geoip_size)}) · обновлен ${formatDate(geoStatus.geoip_modified || geoStatus.last_update)}`
    : (geoRules.enabled ? "Отсутствует на диске" : "Отключен");
  $("routing-geoip-status").textContent = geoipText;

  const geositeText = geoStatus.geosite_exists
    ? `Загружен (${formatSize(geoStatus.geosite_size)}) · обновлен ${formatDate(geoStatus.geosite_modified || geoStatus.last_update)}`
    : (geoRules.enabled ? "Отсутствует на диске" : "Отключен");
  $("routing-geosite-status").textContent = geositeText;

  const autoupdateText = geoRules.enabled
    ? (geoRules.auto_update ? `Включено (каждые ${geoRules.update_interval || "24h"})` : "Выключено вручную")
    : "Правила GeoIP отключены";
  $("routing-autoupdate").textContent = autoupdateText;
  $("routing-ru-egress").textContent = data.disallow_ru_egress ? "Запрещен (только свободные юрисдикции)" : "Разрешен (с ограничениями цензуры)";
  $("routing-geoip-url").textContent = geoRules.geoip_url || "—";
  $("routing-geosite-url").textContent = geoRules.geosite_url || "—";
  $("routing-interval").textContent = geoRules.update_interval || "—";
}

const routingDialog = $("routing-dialog");
$("routing-open-dialog").addEventListener("click", () => {
  if (currentRoutingState) {
    $("input-routing-suffixes").value = (currentRoutingState.direct_suffixes || []).join(", ");
    $("input-routing-domains").value = (currentRoutingState.direct_domains || []).join(", ");
    const gr = currentRoutingState.geo_rules || {};
    $("input-routing-geo-enabled").checked = !!gr.enabled;
    $("input-routing-geo-autoupdate").checked = !!gr.auto_update;
    $("input-routing-disallow-ru").checked = !!currentRoutingState.disallow_ru_egress;
    $("input-routing-geoip-url").value = gr.geoip_url || "";
    $("input-routing-geosite-url").value = gr.geosite_url || "";
    $("input-routing-interval").value = gr.update_interval || "24h";
  }
  routingDialog.showModal();
});

$("routing-close").addEventListener("click", () => routingDialog.close());
$("routing-cancel").addEventListener("click", () => routingDialog.close());

$("routing-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const rawSuffixes = $("input-routing-suffixes").value;
  const rawDomains = $("input-routing-domains").value;

  const parseList = (str) =>
    str.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s.length > 0);

  const directSuffixes = parseList(rawSuffixes);
  const directDomains = parseList(rawDomains);

  const payload = {
    direct_suffixes: directSuffixes,
    direct_domains: directDomains,
    disallow_ru_egress: $("input-routing-disallow-ru").checked,
    geo_rules: {
      enabled: $("input-routing-geo-enabled").checked,
      auto_update: $("input-routing-geo-autoupdate").checked,
      geoip_url: $("input-routing-geoip-url").value.trim(),
      geosite_url: $("input-routing-geosite-url").value.trim(),
      update_interval: $("input-routing-interval").value.trim() || "24h"
    }
  };

  try {
    const updated = await request("/api/admin/routing", {
      method: "PUT",
      body: payload
    }, true);
    currentRoutingState = updated;
    renderRouting(updated);
    routingDialog.close();
    notify("Правила маршрутизации успешно сохранены");
  } catch (error) {
    notify(error.message, true);
  }
});

$("routing-update-geo").addEventListener("click", async () => {
  const btn = $("routing-update-geo");
  btn.disabled = true;
  btn.textContent = "Загрузка...";
  try {
    const status = await request("/api/admin/routing/geo/update", {
      method: "POST"
    }, true);
    if (currentRoutingState) {
      currentRoutingState.geo_status = status;
      renderRouting(currentRoutingState);
    } else {
      await loadRouting();
    }
    notify("Базы GeoIP/GeoSite успешно обновлены");
  } catch (error) {
    notify("Ошибка обновления GeoIP: " + error.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Обновить GeoIP сейчас";
  }
});

setView(location.hash.slice(1) || "overview");
$("admin-password").focus();
loadSelf();

function onionStatusText(status) {
  return {disabled:"Выключен",pending:"Ожидает применения",disabling:"Отключается",unavailable:"Нет готового Tor-маршрута",ready:"Маршрут готов"}[status] || "Статус неизвестен";
}
async function toggleOnion(client) {
  try {
    await request(`/api/admin/clients/${encodeURIComponent(client.id)}`, {method:"PATCH",body:{onion_enabled:!client.onion_enabled}}, true);
    await loadClients();
    notify("Настройка сохранена. Дождитесь изменения статуса доступа к .onion.");
  } catch (error) { notify(error.message, true); }
}
function onionGuide(platform, browser) {
  if (platform === "ios") return [
    "Для прямого доступа к .onion через Hydrat на iPhone и iPad пока нет подтверждённой инструкции. Настройки about:config из Firefox на Android и компьютере к iOS не применяются.",
    "Обычные сайты продолжат работать через WireGuard. Инструкция ниже доступна для Android с Firefox Nightly и для Firefox на компьютере."
  ];
  const enable = "В Hydrat включите «Доступ к .onion через Tor» у своего клиента (если нет прав — попросите администратора). Включите WireGuard и дождитесь статуса «Маршрут готов» в «Моём подключении».";
  const preference = "В адресной строке Firefox откройте about:config. Найдите network.dns.blockDotOnion и переключите значение на false.";
  const open = "Откройте полный адрес сайта с http:// или https:// перед .onion, чтобы браузер не отправил его в поиск. Используйте адрес с официального сайта сервиса. Прокси в браузере настраивать не нужно.";
  const restore = "Чтобы вернуть настройки, установите network.dns.blockDotOnion=true и восстановите прежние настройки DNS. Доступ можно выключить в Hydrat.";
  if (platform === "android") return [
    enable,
    browser === "firefox"
      ? "Откройте Firefox Nightly от Mozilla. В обычном Firefox для Android доступ к about:config ограничен."
      : "Для Chrome, Edge, Brave и других браузеров на Android нет подтверждённой настройки доступа к .onion через Hydrat. Для этого способа используйте Firefox Nightly от Mozilla и выполните следующие шаги.",
    preference,
    "В настройках Firefox найдите «DNS через HTTPS» и выберите «Выкл.», чтобы использовался DNS VPN.",
    "Если в настройках Android задан сторонний «Частный DNS» (Private DNS), временно отключите его. В конфигурации WireGuard сохраните DNS Hydrat — обычно 10.44.0.1.",
    open,
    restore
  ];
  const steps = [
    enable,
    preference,
    "В настройках Firefox → «Приватность и защита» → «DNS через HTTPS» выберите «Выкл.». Сохраните DNS из WireGuard-конфига Hydrat и запомните прежние настройки.",
    open,
    restore
  ];
  if (browser !== "firefox") steps.unshift("Для Chrome, Edge, Brave, Safari и других браузеров на компьютере нет проверенной универсальной настройки: браузер может блокировать .onion до DNS-запроса. Для доступа через Hydrat откройте Firefox и выполните следующие шаги.");
  return steps;
}

function renderOnionGuide() {
  const target = $("onion-guide-steps");
  target.replaceChildren(...onionGuide($("onion-platform").value, $("onion-browser").value).map((text) => node("li", "", text)));
}
$("onion-platform").addEventListener("change", renderOnionGuide);
$("onion-browser").addEventListener("change", renderOnionGuide);
renderOnionGuide();

let i2pEntries = [];
let i2pEntryOffset = 0;
let i2pLoadVersion = 0;
const i2pPermissionText = (status) => ({disabled:"Выключен",disabling:"Выключается",pending:"Ожидает применения",enabled:"Разрешён",unavailable:"Недоступен"}[status] || "Выключен");
async function toggleI2P(client) {
  try {
    await request(`/api/admin/clients/${encodeURIComponent(client.id)}`, {method:"PATCH",body:{i2p_enabled:!client.i2p_enabled}}, true);
    await loadClients(); notify("Настройка I2P сохранена.");
  } catch(error) { notify(error.message,true); }
}
function renderI2PEntries() {
  const target=$("i2p-entries");target.replaceChildren();
  for(const entry of i2pEntries) {
    const row=node("article","data-row");const info=node("div","identity");info.append(node("strong","",entry.name),node("small","",entry.destination),node("small","",entry.source==="manual"?"Ручная запись":"Из подписки"));
    row.append(info,button("Изменить",()=>{$("i2p-name").value=entry.name;$("i2p-destination").value=entry.public_destination||entry.destination;$("i2p-name").focus();}),button("Удалить",async()=>{if(!confirm(`Удалить ${entry.name}? Открытые соединения к этому адресу закроются.`))return;await i2pAction(`/entries/${encodeURIComponent(entry.name)}`,{method:"DELETE"});}));target.append(row);
  }
  if(!target.children.length)target.textContent="Адресов не найдено. Адреса .b32.i2p можно открывать без записи в книге.";
}
async function loadI2P() {
  const version=++i2pLoadVersion;
  try {
    const query=encodeURIComponent($("i2p-search").value.trim());
    const data=await request(`/api/admin/i2p?offset=${i2pEntryOffset}&q=${query}`,{},true);
    if(version!==i2pLoadVersion)return;
    i2pEntries=data.entries||[];renderI2PEntries();
    const navigation=node("div","button-row");
    navigation.append(node("small","",`Адресов: ${data.total ?? i2pEntries.length}`));
    if(i2pEntryOffset>0)navigation.append(button("Предыдущие адреса",()=>{i2pEntryOffset=Math.max(0,i2pEntryOffset-50);return loadI2P();}));
    if(data.next_offset!=null)navigation.append(button("Следующие адреса",()=>{i2pEntryOffset=data.next_offset;return loadI2P();}));
    $("i2p-entries").append(navigation);
    const runtime=data.runtime||{};const state={sleeping:"Спит — запустится при обращении",starting:"Запускается и строит туннели",warm:"Прогрет",active:"Есть открытые соединения",error:"Остановлен после ошибки проверки",unavailable:"Компонент I2P недоступен"}[runtime.state]||"Состояние неизвестно";
    $("i2p-status").textContent=`${state}. Соединений: ${runtime.streams||0}. Ретрансляция чужого трафика запрещена.${data.available?"":" I2P недоступен: проверьте компонент и его состояние на сервере."}`;
    if(document.activeElement!==$("i2p-warm"))$("i2p-warm").value=String(data.warm_seconds/60);
    const target=$("i2p-subscriptions");target.replaceChildren();
    for(const feed of data.subscriptions||[]) {
      const row=node("article","data-row");const info=node("div","identity");info.append(node("strong","",feed.url),node("small","",`${feed.refreshing?"Обновляется · ":""}${feed.enabled?"Включена":"Выключена"}${feed.error?" · "+feed.error:""}`));row.append(info);
      row.append(button(feed.enabled?"Отключить":"Включить",()=>i2pAction(`/subscriptions/${feed.id}`,{method:"PATCH",body:{enabled:!feed.enabled}})),button("Обновить",()=>i2pAction(`/subscriptions/${feed.id}/refresh`,{method:"POST"})),button("Удалить",async()=>{if(confirm("Удалить подписку? Уже добавленные адреса останутся."))await i2pAction(`/subscriptions/${feed.id}`,{method:"DELETE"});}));
      const conflicts=node("div","i2p-conflict");
      renderI2PConflicts(feed.id,conflicts,{entries:feed.conflicts||[],total:feed.conflict_total ?? (feed.conflicts||[]).length,next_offset:feed.next_conflict_offset},0);
      row.append(conflicts);
      target.append(row);
    }
    if(!target.children.length)target.textContent="Подписок нет";
  } catch(error) {if(version!==i2pLoadVersion)return;$("i2p-status").textContent=`I2P недоступен: ${error.message}. Обычные маршруты работают независимо.`;}
}
function renderI2PConflicts(id,target,page,offset) {
  target.replaceChildren();
  if(!page.total)return;
  target.append(node("small","",`Конфликтов: ${page.total}`));
  for(const conflict of page.entries||[]) {
    const item=node("div","i2p-conflict");
    item.append(node("p","",`Подписка предлагает изменить ${conflict.name} на ${conflict.destination}`),
      button("Принять",async()=>{if(confirm(`Заменить адрес ${conflict.name}? Его открытые соединения закроются.`))await i2pAction(`/subscriptions/${id}/conflicts`,{method:"POST",body:{name:conflict.name,accept:true}});}),
      button("Оставить прежний",()=>i2pAction(`/subscriptions/${id}/conflicts`,{method:"POST",body:{name:conflict.name,accept:false}})));
    target.append(item);
  }
  const changePage=async(next)=>{
    try {const data=await request(`/api/admin/i2p/subscriptions/${encodeURIComponent(id)}/conflicts?offset=${next}`,{},true);renderI2PConflicts(id,target,data,next);}
    catch(error){notify(error.message,true);}
  };
  const navigation=node("div","button-row");
  if(offset>0)navigation.append(button("Предыдущие конфликты",()=>changePage(Math.max(0,offset-10))));
  if(page.next_offset!=null)navigation.append(button("Следующие конфликты",()=>changePage(page.next_offset)));
  target.append(navigation);
}
async function i2pAction(path,options) {try{await request(`/api/admin/i2p${path}`,options,true);await loadI2P();notify("Сохранено");return true;}catch(error){notify(error.message,true);return false;}}
$("i2p-settings").addEventListener("toggle",()=>{if($("i2p-settings").open&&adminToken)loadI2P();});
$("i2p-refresh").addEventListener("click",loadI2P);
$("i2p-wake").addEventListener("click",()=>i2pAction("/wake",{method:"POST"}));
$("i2p-search").addEventListener("input",()=>{i2pEntryOffset=0;return loadI2P();});
$("i2p-warm-form").addEventListener("submit",event=>{event.preventDefault();i2pAction("/settings",{method:"PUT",body:{warm_seconds:Number($("i2p-warm").value)*60}});});
$("i2p-entry-form").addEventListener("submit",async event=>{
 event.preventDefault();const name=$("i2p-name").value.trim().toLowerCase();const destination=$("i2p-destination").value.trim();
 const existing=i2pEntries.find(e=>e.name===name);const replace=!!existing;
 if(replace&&!confirm(`Заменить адрес ${name}? Открытые соединения к прежнему адресу закроются.`))return;
 if(await i2pAction("/entries",{method:"PUT",body:{name,destination,replace}})){$("i2p-name").value="";$("i2p-destination").value="";}
});
$("i2p-preview-button").addEventListener("click",async()=>{try{const p=await request("/api/admin/i2p/import/preview",{method:"POST",body:{text:$("i2p-import-text").value}},true);$("i2p-preview").textContent=`Записей: ${p.valid}. Конфликтов: ${p.conflicts.length}. Ошибок: ${p.errors.length}. ${p.errors.join("; ")}`;}catch(e){notify(e.message,true);}});
$("i2p-import-button").addEventListener("click",async()=>{
 try{const text=$("i2p-import-text").value;const p=await request("/api/admin/i2p/import/preview",{method:"POST",body:{text}},true);if(p.errors.length){notify("Исправьте ошибки импорта: "+p.errors.join("; "),true);return;}
 const replace=p.conflicts.length>0;if(replace&&!confirm(`Изменятся адреса: ${p.conflicts.map(c=>c.name).join(", ")}. Открытые соединения к ним закроются. Продолжить?`))return;
 await i2pAction("/import",{method:"POST",body:{text,replace}});
 }catch(e){notify(e.message,true);}
});
$("i2p-export").addEventListener("click",async()=>{try{const r=await request("/api/admin/i2p/export",{},true,true);const url=URL.createObjectURL(await r.blob());const link=document.createElement("a");link.href=url;link.download="hosts.txt";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){notify(e.message,true);}});
$("i2p-subscription-form").addEventListener("submit",async event=>{event.preventDefault();if(await i2pAction("/subscriptions",{method:"POST",body:{url:$("i2p-subscription-url").value.trim(),enabled:true}}))$("i2p-subscription-url").value="";});
