import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import {createContext, runInContext} from "node:vm";

const app = readFileSync(new URL("./web/app.js", import.meta.url), "utf8");
const html = readFileSync(new URL("./web/index.html", import.meta.url), "utf8");

test("idle client is not presented as active and keeps bootstrap separate", async () => {
  const page = dashboard(async () => new Response(JSON.stringify({clients:[{id:"alice",name:"Alice",address:"10.44.0.2/32",paused:false,connection_state:"inactive",route_reserved:false}],assignments:[{client_id:"alice",tcp_outbound:"bootstrap",udp_outbound:"bootstrap"}]}),{status:200}));
  await runInContext('adminToken="token"; loadClients()', page.context);
  const row = page.elements.get("admin-clients").children[0];
  const texts = (element) => [element.textContent,...(element.children||[]).flatMap(texts)];
  assert.ok(texts(row).some(text => text.includes("резервация освобождена")));
  assert.ok(!texts(row).includes("Активен"));
});

function dashboard(fetchAdmin) {
  let doc;
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(([, id]) => [id, {
    tagName: "div",
    id,
    value: "",
    className: "",
    textContent: "",
    children: [],
    listeners: {},
    addEventListener(type, listener) { this.listeners[type] = listener; },
    focus() { doc.activeElement = this; },
    append(...items) { this.children.push(...items); },
    replaceChildren(...items) { this.children = [...items]; }
  }]));
  doc = {
    activeElement: null,
    getElementById: (id) => elements.get(id),
    createElement: (tag) => ({
      tagName: tag,
      value: "",
      className: "",
      textContent: "",
      children: [],
      listeners: {},
      addEventListener(type, listener) { this.listeners[type] = listener; },
      append(...items) { this.children.push(...items); },
      replaceChildren(...items) { this.children = [...items]; }
    }),
    querySelector: () => ({textContent: ""}),
    querySelectorAll: () => []
  };
  const reloads = [];
  const location = {
    hash: "#system",
    reload() {
      reloads.push({token: runInContext("adminToken", context), password: elements.get("admin-password").value, hash: this.hash});
    }
  };
  const context = createContext({
    document: doc, location, Headers,
    confirm: () => true,
    history: {replaceState(_state, _title, hash) { location.hash = hash; }},
    fetch: (url, options) => url === "/api/me" ? new Promise(() => {}) : fetchAdmin(url, options),
    setTimeout: () => 0, clearTimeout() {}
  });
  runInContext(app, context);
  return {context, document: doc, elements, reloads};
}

test("a fresh dashboard focuses admin login", () => {
  const page = dashboard();
  assert.equal(page.document.activeElement, page.elements.get("admin-password"));
});

for (const scenario of [
  {name: "successful logout", trigger: "logout", status: 204},
  {name: "rejected revocation", trigger: "logout", status: 500},
  {name: "unreachable revocation", trigger: "logout", networkError: true},
  {name: "expired logout", trigger: "logout", status: 401},
  {name: "admin JSON 401", trigger: "request", status: 401},
  {name: "admin artifact 401", trigger: "raw", status: 401},
  {name: "login 401", trigger: "login", status: 401}
]) {
  test(`${scenario.name} clears credentials before reloading the initial dashboard`, async () => {
    const requests = [];
    const page = dashboard(async (url, options) => {
      requests.push({url, method: options.method, authorization: options.headers.get("Authorization")});
      if (scenario.networkError) throw new TypeError("Failed to fetch");
      return new Response(null, {status: scenario.status});
    });
    runInContext('adminToken = "live-token"', page.context);
    page.elements.get("admin-password").value = "secret";

    if (scenario.trigger === "logout") {
      await page.elements.get("admin-logout").listeners.click();
      assert.deepEqual(requests, [{url: "/api/admin/session", method: "DELETE", authorization: "Bearer live-token"}]);
    } else if (scenario.trigger === "login") {
      await page.elements.get("auth-form").listeners.submit({preventDefault() {}});
    } else {
      await assert.rejects(runInContext(`request("/api/admin/clients/example/config.json", {}, true, ${scenario.trigger === "raw"})`, page.context), /HTTP 401/);
    }

    assert.ok(page.reloads.length > 0, "session reset must reload to discard all admin DOM, state and object URLs");
    for (const snapshot of page.reloads) {
      assert.deepEqual(snapshot, {token: "", password: "", hash: "#overview"});
    }
  });
}

test("public 401 does not restart the dashboard", async () => {
  const page = dashboard(async () => new Response(null, {status: 401}));
  await assert.rejects(runInContext('request("/api/public")', page.context), /HTTP 401/);
  assert.equal(page.reloads.length, 0);
});

test("login clears the password before dashboard requests finish", async () => {
  const page = dashboard(async (url) => url === "/api/admin/session"
    ? Response.json({token: "live-token"})
    : new Promise(() => {}));
  page.elements.get("admin-password").value = "secret";
  page.elements.get("auth-form").listeners.submit({preventDefault() {}});
  await new Promise(setImmediate);
  assert.equal(page.elements.get("admin-password").value, "");
  assert.equal(runInContext("adminToken", page.context), "live-token");
});

test("loadSources excludes pending_delete sources so UI does not misleadingly keep deleted sources", async () => {
  const page = dashboard(async (url) => {
    if (url === "/api/admin/sources") {
      return Response.json({
        sources: [
          {id: "src_active", label: "Active VLESS", kind: "vless", enabled: true, pending_delete: false, candidate_count: 1},
          {id: "src_deleted", label: "Deleted VLESS", kind: "vless", enabled: false, pending_delete: true, candidate_count: 1}
        ]
      });
    }
    return Response.json({});
  });
  runInContext('adminToken = "live-token"', page.context);
  await runInContext("loadSources()", page.context);
  const target = page.elements.get("admin-sources");
  assert.equal(target.children.length, 1);
  assert.ok(!JSON.stringify(target.children).includes("Deleted VLESS"));
});

test("loadSources marks inventory empty when all sources are pending_delete", async () => {
  const page = dashboard(async (url) => {
    if (url === "/api/admin/sources") {
      return Response.json({
        sources: [
          {id: "src_deleted", label: "Deleted VLESS", kind: "vless", enabled: false, pending_delete: true, candidate_count: 1}
        ]
      });
    }
    return Response.json({});
  });
  runInContext('adminToken = "live-token"', page.context);
  await runInContext("loadSources()", page.context);
  const target = page.elements.get("admin-sources");
  assert.equal(target.children.length, 0);
  assert.equal(target.className, "data-list empty");
  assert.equal(target.textContent, "Источников пока нет");
});

test("deleteSource deletes source with Bearer token and updates UI without logging out", async () => {
  const requests = [];
  let deleted = false;
  const page = dashboard(async (url, options = {}) => {
    requests.push({url, method: options.method || "GET", auth: options.headers?.get("Authorization")});
    if (url === "/api/admin/sources/src_1" && options.method === "DELETE") {
      deleted = true;
      return new Response(null, {status: 204});
    }
    if (url === "/api/admin/sources") {
      return Response.json({
        sources: deleted
          ? [{id: "src_1", label: "VLESS", kind: "vless", enabled: false, pending_delete: true, candidate_count: 1}]
          : [{id: "src_1", label: "VLESS", kind: "vless", enabled: true, pending_delete: false, candidate_count: 1}]
      });
    }
    if (url === "/api/admin/system") {
      return Response.json({working_pool_by_kind: {}, effective_capacity: {}});
    }
    return Response.json({});
  });
  runInContext('adminToken = "live-token"', page.context);
  await runInContext('deleteSource({id: "src_1", label: "VLESS"})', page.context);
  assert.equal(page.reloads.length, 0, "deleteSource must not reload or log out");
  assert.equal(runInContext("adminToken", page.context), "live-token");
  assert.ok(requests.some((r) => r.url === "/api/admin/sources/src_1" && r.method === "DELETE" && r.auth === "Bearer live-token"));
  const target = page.elements.get("admin-sources");
  assert.equal(target.children.length, 0);
  assert.equal(target.textContent, "Источников пока нет");
});

test("onion guide configures direct Hydrat access without a separate Tor browser", () => {
  const page = dashboard();
  for (const platform of ["desktop", "android", "ios"]) {
    for (const browser of ["firefox", "chrome", "edge", "brave", "safari", "other"]) {
      const guide = runInContext(`onionGuide("${platform}", "${browser}").join(" ")`, page.context);
      assert.ok(guide.length > 80);
      assert.doesNotMatch(guide, /Tor Browser|Onion Browser|собственн.*Tor|окно с Tor/);
      if (platform === "ios") assert.match(guide, /не поддерживается|нет подтверждённой/);
      if (platform === "android") {
        for (const instruction of [/Firefox Nightly/, /about:config/, /network.dns.blockDotOnion/, /false/, /DNS через HTTPS/, /Частный DNS/, /WireGuard/, /Маршрут готов/]) assert.match(guide, instruction);
      }
      assert.doesNotMatch(guide, /отключите проверку сертификатов/i);
    }
  }
  assert.match(runInContext('onionGuide("desktop", "firefox").join(" ")', page.context), /network.dns.blockDotOnion/);
});

test("onion permission button uses Bearer session and displays applied status", async () => {
  let enabled = false;
  const requests = [];
  const page = dashboard(async (url, options = {}) => {
    if (options.method === "PATCH") {
      requests.push({url, auth: options.headers.get("Authorization"), body: JSON.parse(options.body)});
      enabled = JSON.parse(options.body).onion_enabled;
      return new Response(null, {status: 204});
    }
    return Response.json({clients:[{id:"alice", name:"Alice", address:"10.44.0.2/32", onion_enabled:enabled, onion_status:enabled ? "pending" : "disabling"}]});
  });
  await runInContext('adminToken="session"; toggleOnion({id:"alice",onion_enabled:false})', page.context);
  const texts = (element) => [element.textContent,...(element.children||[]).flatMap(texts)];
  assert.ok(texts(page.elements.get("admin-clients")).includes(".onion: Ожидает применения"));
  const disable = page.elements.get("admin-clients").children[0].children.at(-1).children.find(button => button.textContent === "Выключить .onion");
  await disable.listeners.click();
  assert.ok(texts(page.elements.get("admin-clients")).includes(".onion: Отключается"));
  assert.deepEqual(requests, [true, false].map(onion_enabled => ({url:"/api/admin/clients/alice", auth:"Bearer session", body:{onion_enabled}})));
});

test("onion shortcut opens its guide inside System and preserves old links", () => {
  const page = dashboard();
  for (const target of ["onion", "system-onion"]) {
    runInContext(`setView("${target}")`, page.context);
    assert.equal(page.elements.get("page-title").textContent, "Система");
    assert.equal(runInContext("location.hash", page.context), "#system-onion");
    assert.equal(page.elements.get("onion-guide").open, true);
  }
});

test("I2P stays in System and does not claim websites are ready while sleeping", async () => {
  assert.ok(html.includes('id="i2p-settings"'));
  assert.ok(!html.includes('data-nav="i2p"'));
  const page = dashboard(async () => new Response(JSON.stringify({runtime:{state:"sleeping",streams:0},available:true,no_transit:true,warm_seconds:7200,entries:[],subscriptions:[]}),{status:200}));
  await runInContext('adminToken="token"; loadI2P()',page.context);
  assert.match(page.elements.get("i2p-status").textContent,/Спит/);
  assert.doesNotMatch(page.elements.get("i2p-status").textContent,/Сайты готовы/);
});

test("I2P pages addresses and conflicts without losing search or authorization", async () => {
  const calls=[];
  const page=dashboard(async(url,options)=>{
    calls.push({url,auth:options.headers.get("Authorization")});
    if(url.includes("/conflicts"))return new Response(JSON.stringify({entries:[{name:"later.i2p",destination:"later.b32.i2p"}],total:11,next_offset:null}));
    const later=url.includes("offset=50");
    return new Response(JSON.stringify({runtime:{state:"warm"},available:true,warm_seconds:7200,entries:[{name:later?"second.i2p":"first.i2p",destination:"test.b32.i2p"}],total:51,next_offset:later?null:50,subscriptions:[{id:"feed",url:"https://example.org/hosts",enabled:true,conflicts:[{name:"first.i2p",destination:"new.b32.i2p"}],conflict_total:11,next_conflict_offset:10}]}));
  });
  const all=e=>[e,...(e.children||[]).flatMap(all)];
  const click=async(root,text)=>{const b=all(root).find(e=>e.tagName==="button"&&e.textContent===text);assert.ok(b,`missing ${text}`);await b.listeners.click();};
  await runInContext('adminToken="token"; loadI2P()',page.context);
  await click(page.elements.get("i2p-entries"),"Следующие адреса");
  assert.ok(all(page.elements.get("i2p-entries")).some(e=>e.textContent==="second.i2p"));
  await click(page.elements.get("i2p-subscriptions"),"Следующие конфликты");
  assert.ok(all(page.elements.get("i2p-subscriptions")).some(e=>e.textContent.includes("later.i2p")));
  page.elements.get("i2p-search").value="second";
  await page.elements.get("i2p-search").listeners.input();
  assert.ok(calls.some(c=>c.url.includes("offset=0&q=second")));
  assert.ok(calls.every(c=>c.auth==="Bearer token"));
});

test("I2P shortcut opens instructions without administrator authentication", () => {
  const page = dashboard(() => { throw new Error("guide must not fetch protected data"); });
  runInContext('setView("system-i2p")', page.context);
  assert.equal(page.elements.get("page-title").textContent, "Система");
  assert.equal(runInContext("location.hash", page.context), "#system-i2p");
  assert.equal(page.elements.get("i2p-settings").open, true);
  assert.ok(html.includes('data-nav="system-i2p"'));
});

test("system shows healthy API separately from unready routing", async () => {
  const page = dashboard(async (url) => new Response(JSON.stringify(String(url).includes('/system') ? {health_status:"ok",readiness_status:"controller unavailable: reserve_not_ready"} : {}),{status:200}));
  await runInContext('adminToken="token"; loadSystem()', page.context);
  const texts=page.elements.get("system-details").children.map(item=>item.textContent);
  assert.ok(texts.includes("Шлюз/API"));
  assert.ok(texts.includes("Готовность маршрутизации"));
  assert.ok(texts.includes("controller unavailable: reserve_not_ready"));
});
