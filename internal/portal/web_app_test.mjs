import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import {createContext, runInContext} from "node:vm";

const app = readFileSync(new URL("./web/app.js", import.meta.url), "utf8");
const html = readFileSync(new URL("./web/index.html", import.meta.url), "utf8");

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
