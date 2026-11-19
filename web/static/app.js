// KyGate console: reports over the reporting API, and administration over the admin API.
// Every value from the API is inserted as text, never as HTML.
"use strict";

const state = { token: "", range: "7d", info: null };

// ---------- storage (per-viewer convenience only) ----------
function store(key, value) {
  try { if (value === undefined) return sessionStorage.getItem(key); if (value === null) sessionStorage.removeItem(key); else sessionStorage.setItem(key, value); } catch (_) { /* storage unavailable */ }
  return null;
}
function prefs(key, value) {
  try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (_) { /* storage unavailable */ }
  return null;
}

// ---------- DOM helpers ----------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const SVG = "http://www.w3.org/2000/svg";
function s(tag, attrs) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}

// ---------- formatting ----------
const nf = new Intl.NumberFormat();
function money(v) {
  if (!v) return "$0.00";
  // Small amounts keep two significant digits: one short question can cost
  // $0.0000085, which four decimals would show as $0.0000.
  if (Math.abs(v) < 0.01) return "$" + Number(v.toPrecision(2)).toFixed(Math.min(12, 1 - Math.floor(Math.log10(Math.abs(v)))));
  return "$" + v.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function count(v) { return nf.format(v || 0); }
function compact(v) {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(v || 0);
}
function pct(a, b) { return b ? Math.round((a / b) * 1000) / 10 + "%" : "–"; }
function when(t) {
  const d = new Date(t);
  return isNaN(d) ? "" : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function tokens(e) { return (e.input_tokens || 0) + (e.cached_input_tokens || 0) + (e.cache_write_tokens || 0) + (e.output_tokens || 0); }

const OUTCOME = {
  ok: ["good", "✓ ok"], blocked: ["critical", "⛔ blocked"], refused: ["warning", "⚠ refused"],
  error: ["critical", "✕ error"], client_error: ["warning", "! client error"], canceled: ["", "– canceled"],
  over_budget: ["critical", "$ over budget"], rate_limited: ["warning", "⏱ rate limited"],
};
function outcomePill(o) { const [cls, label] = OUTCOME[o] || ["", o]; return h("span", { class: "pill " + cls }, label); }
function cachePill(c, sem) {
  if (c === "hit" && sem === "hit") return h("span", { class: "pill good" }, "semantic hit");
  if (c === "hit") return h("span", { class: "pill good" }, "hit");
  if (sem === "would_hit") return h("span", { class: "pill", title: "shadow mode: the semantic cache would have answered" }, "miss · would hit");
  if (c === "coalesced") return h("span", { class: "pill good", title: "an identical request was in flight: this one shared its answer" }, "coalesced");
  if (c === "miss") return h("span", { class: "pill" }, "miss");
  if (c === "bypass") return h("span", { class: "pill" }, "bypass");
  return h("span", { class: "muted" }, "–");
}
function semanticText(e) {
  switch (e.semantic) {
    case "hit": return "served a stored answer to a look-alike question (similarity " + e.similarity + ")";
    case "would_hit": return "shadow mode: would have served a stored answer (similarity " + e.similarity + "); the real answer " +
      (e.semantic_check === "agree" ? "agreed with it" : e.semantic_check === "disagree" ? "differed from it" : "was not compared");
    case "miss": return "looked up, no look-alike stored";
    case "error": return "skipped: the embeddings model could not be reached";
  }
  return "not eligible (needs a short plain question, nothing detected, no tools) or off";
}

// semanticCard reports the semantic cache: what it served, and in shadow mode
// what it would have served and how often that agreed with the real answer.
function semanticCard(t) {
  const sem = state.info.policy.semantic || {};
  if (!sem.enabled && !t.semantic_lookups) {
    return card("Semantic cache", h("p", { class: "muted" },
      "Off. It answers look-alike questions (\"what's the capital of france\" after \"What is the capital of France?\") from the cache. " +
      "Turn it on in the policy (cache.semantic) with an embeddings model, such as Ollama's nomic-embed-text."));
  }
  const checked = t.semantic_agree + t.semantic_disagree;
  const shadow = sem.mode !== "serve";
  return card("Semantic cache" + (shadow ? " · shadow mode" : ""),
    shadow ? h("p", { class: "muted" }, "Shadow mode changes nothing: the model answers every request, and KyGate records the hits it would have served. " +
      "Switch to serve (cache.semantic.mode) when the disagreement rate below is low enough for you.") : null,
    !sem.connected && sem.enabled ? h("div", { class: "banner warn" }, h("strong", {}, "No embeddings model"),
      "No provider connection is named \"" + sem.connection + "\". Set KYGATE_LOCAL_" + String(sem.connection || "").toUpperCase() + " and restart.") : null,
    h("div", { class: "tiles" },
      tile("Look-ups", count(t.semantic_lookups), t.semantic_errors ? count(t.semantic_errors) + " skipped on errors" : "eligible questions"),
      tile("Served", count(t.semantic_hits), money(t.semantic_avoided_usd) + " avoided"),
      tile("Would have served", count(t.semantic_would_hit), money(t.semantic_would_avoid_usd) + " it would have saved"),
      tile("Answers differed", checked ? pct(t.semantic_disagree, checked) : "–",
        checked ? count(t.semantic_disagree) + " of " + count(checked) + " compared; an estimate of wrong answers" : "measured in shadow mode")));
}

// cacheFile describes the exact cache kept on disk (cache.db), from /api/v1/info.
function cacheFile(d) {
  if (!d || d.state === "off") return "off: the policy keeps the exact cache in memory only (cache.exact.persist)";
  if (d.state === "unavailable") return h("span", {}, h("span", { class: "pill warning" }, "unavailable"), " in memory only. " + (d.error || ""));
  return count(d.entries) + " entries, " + compact(d.bytes) + "B of " + compact(d.max_bytes) + "B, " + count(d.hits) + " hits since start" +
    (d.errors ? ", " + count(d.errors) + " errors" : "");
}

function semanticSetup(i) {
  const sem = i.policy.semantic || {};
  if (!sem.enabled) return "off (cache.semantic.enabled)";
  const st = i.semantic || {};
  return sem.mode + ", per " + sem.scope + ", similarity ≥ " + sem.min_similarity + ", TTL " + sem.ttl + ", model " + sem.model + " on " + sem.connection +
    (sem.connected ? "" : " (not connected)") + "; " + count(st.entries) + " entries in " + (st.where || "memory") +
    ", " + count(st.rejected) + " stopped by the hard checks since start";
}

// ---------- API ----------
// The session is a cookie (HttpOnly, SameSite=Strict); every change sends the
// session's CSRF value back.
async function api(path, params) {
  const q = new URLSearchParams(params || {});
  const res = await fetch("/api/v1/" + path + (q.toString() ? "?" + q : ""), { credentials: "same-origin" });
  if (res.status === 401) { showLogin("Your session has ended: sign in again."); throw new Error("unauthorized"); }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || "request failed (" + res.status + ")");
  return body;
}
async function apiWrite(method, path, body, yaml) {
  const headers = { "X-KyGate-CSRF": (state.me && state.me.csrf) || "" };
  if (body !== undefined) headers["Content-Type"] = yaml ? "application/yaml" : "application/json";
  const res = await fetch("/api/v1/" + path, { method, headers, credentials: "same-origin",
    body: body === undefined ? undefined : (yaml ? body : JSON.stringify(body)) });
  if (res.status === 401) { showLogin("Your session has ended: sign in again."); throw new Error("unauthorized"); }
  const text = await res.text();
  let out = {};
  try { out = text ? JSON.parse(text) : {}; } catch (_) { out = { text }; }
  if (!res.ok) throw new Error(out.error || "request failed (" + res.status + ")");
  return out;
}

// ---------- shell ----------
async function showLogin(msg) {
  state.me = null;
  store("kygate.token", null); // an older console kept the token here
  document.getElementById("app").hidden = true;
  document.getElementById("login").hidden = false;
  const err = document.getElementById("login-error");
  err.hidden = !msg; err.textContent = msg || "";
  try {
    const cfg = await (await fetch("/auth/config", { credentials: "same-origin" })).json();
    document.getElementById("sso-box").hidden = !cfg.sso;
    if (cfg.sso) document.getElementById("sso-link").textContent = "Sign in with " + cfg.sso_name;
    document.getElementById("token-submit").textContent = cfg.sso ? "Open with the admin token (recorded)" : "Open the console";
  } catch (_) { /* the page still offers the token */ }
}
async function signOut() {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
  showLogin();
}

async function start() {
  state.range = prefs("kygate.range") || "7d";
  document.getElementById("range").value = state.range;
  const res = await fetch("/auth/me", { credentials: "same-origin" }).catch(() => null);
  if (!res || !res.ok) { showLogin(); return; }
  state.me = await res.json();
  try {
    state.info = await api("info");
  } catch (e) {
    if (e.message !== "unauthorized") showLogin(e.message);
    return;
  }
  document.getElementById("who").textContent = state.me.actor + " · " + state.me.role.replace("_", " ") + (state.me.team ? " (" + state.me.team + ")" : "");
  document.getElementById("login").hidden = true;
  document.getElementById("app").hidden = false;
  const tag = document.getElementById("mode-tag");
  const mode = state.info.policy.mode;
  tag.textContent = mode === "monitor" ? "monitor mode" : "v" + state.info.version + " " + (isEnterprise() ? "Enterprise" : "Community") + " · " + state.info.profile;
  tag.className = "tag" + (mode === "monitor" ? " monitor" : "");
  document.getElementById("foot").textContent =
    "KyGate " + state.info.version + " · policy " + state.info.policy.version + " · model API " + state.info.model_api +
    " · signed in as " + state.me.actor + " (" + state.me.role.replace("_", " ") + ")";
  route();
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const token = document.getElementById("token").value.trim();
  document.getElementById("token").value = "";
  const res = await fetch("/auth/token", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
  if (!res.ok) { showLogin("The admin token was not accepted."); return; }
  start();
});
document.getElementById("logout").addEventListener("click", () => signOut());
document.getElementById("refresh").addEventListener("click", () => route());
document.getElementById("range").addEventListener("change", (e) => { state.range = e.target.value; prefs("kygate.range", state.range); route(); });
window.addEventListener("hashchange", route);

const VIEWS = { overview, requests, protection, usage, setup, admin };

async function route() {
  if (!state.me) return;
  const name = (location.hash.slice(1) || "overview").split("/")[0];
  const view = VIEWS[name] || overview;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + name));
  const main = document.getElementById("view");
  main.replaceChildren(h("p", { class: "muted" }, "Loading…"));
  try {
    main.replaceChildren(...(await view()).filter((x) => x !== null && x !== undefined && x !== false));
  } catch (e) {
    if (e.message !== "unauthorized") main.replaceChildren(h("div", { class: "banner warn" }, h("strong", {}, "Could not load this page"), e.message));
  }
}

// ---------- shared pieces ----------
function tile(label, value, sub) {
  return h("div", { class: "tile" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), sub ? h("div", { class: "sub" }, sub) : null);
}
function card(title, ...body) { return h("section", { class: "card" }, title ? h("h2", {}, title) : null, ...body); }
function table(cols, rows, onRow) {
  if (!rows.length) return h("p", { class: "empty" }, "Nothing in this time range yet.");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, cols.map((c) => h("th", { class: c.num ? "num" : null, scope: "col" }, c.label)))),
    h("tbody", {}, rows.map((r) => h("tr", onRow ? { class: "clickable", tabindex: "0", onclick: () => onRow(r), onkeydown: (e) => { if (e.key === "Enter") onRow(r); } } : {},
      cols.map((c) => h("td", { class: c.num ? "num" : null }, c.get(r))))))));
}
function delta(cur, prev) {
  if (!prev) return null;
  const d = ((cur - prev) / prev) * 100;
  return (d >= 0 ? "+" : "") + Math.round(d) + "% vs previous period";
}
function setupBanners() {
  const out = [];
  const i = state.info;
  if (!i.connections) out.push(h("div", { class: "banner warn" }, h("strong", {}, "No provider is configured"),
    "KyGate cannot answer requests yet. Set ANTHROPIC_API_KEY or OPENAI_API_KEY and restart, or run 'kygate provider add'."));
  if (i.policy.mode === "monitor") out.push(h("div", { class: "banner info" }, h("strong", {}, "Monitor mode"),
    "The policy records what it would block or mask, and changes nothing. Requests leave as they arrived."));
  const g = i.guard || {};
  if ((g.needed_for || []).length && (!g.configured || g.state.state !== "ready")) out.push(h("div", { class: "banner warn" },
    h("strong", {}, "The Guard is needed and not ready"),
    "The policy names " + g.needed_for.join(", ") + ", which only the Guard finds. See Protection for what happens meanwhile."));
  for (const w of i.policy.warnings || []) out.push(h("div", { class: "banner info" }, w));
  return out;
}

// ---------- chart: cost vs cost avoided ----------
function costChart(series, bucket) {
  const root = h("div", {});
  root.append(h("div", { class: "legend" },
    h("span", {}, h("span", { class: "sw s1" }), "Spent"),
    h("span", {}, h("span", { class: "sw s2" }), "Avoided by the cache")));
  if (!series.length) { root.append(h("p", { class: "empty" }, "No requests in this time range yet.")); return root; }
  const W = 800, H = 260, L = 56, R = 8, T = 10, B = 28;
  const max = Math.max(...series.map((d) => Math.max(d.cost_usd, d.cost_avoided_usd)), 0.0001);
  const nice = niceMax(max);
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img",
    "aria-label": "Spent and avoided cost per " + bucket + ". The tables below hold the same figures." });
  for (let i = 0; i <= 4; i++) {
    const y = T + (H - T - B) * (1 - i / 4);
    svg.append(s("line", { class: "grid-line", x1: L, x2: W - R, y1: y, y2: y }));
    const t = s("text", { x: L - 6, y: y + 4, "text-anchor": "end" }); t.textContent = money(nice * i / 4); svg.append(t);
  }
  const n = series.length, slot = (W - L - R) / n, gap = 2;
  const bw = Math.max(2, Math.min(28, (slot - 8) / 2 - gap / 2));
  const yOf = (v) => T + (H - T - B) * (1 - v / nice);
  const base = H - B;
  const labelEvery = Math.ceil(n / 10);
  series.forEach((d, i) => {
    const cx = L + slot * i + slot / 2;
    const bar = (v, x, cls) => {
      const y = yOf(v), hgt = Math.max(0, base - y);
      if (hgt <= 0) return;
      const r = Math.min(4, bw / 2, hgt);
      svg.append(s("path", { class: cls, d: `M${x},${base} V${y + r} Q${x},${y} ${x + r},${y} H${x + bw - r} Q${x + bw},${y} ${x + bw},${y + r} V${base} Z` }));
    };
    bar(d.cost_usd, cx - bw - gap / 2, "s1");
    bar(d.cost_avoided_usd, cx + gap / 2, "s2");
    if (i % labelEvery === 0) {
      const t = s("text", { x: cx, y: H - 8, "text-anchor": "middle" });
      t.textContent = bucket === "hour" ? d.key.slice(11, 16) : d.key.slice(5);
      svg.append(t);
    }
    const hit = s("rect", { class: "hit", x: L + slot * i, y: T, width: slot, height: H - T - B });
    hit.addEventListener("mousemove", (e) => showTip(e, [d.key.replace("T", " "),
      ["Spent", money(d.cost_usd)], ["Avoided", money(d.cost_avoided_usd)],
      ["Requests", count(d.requests)], ["Cache hits", count(d.cache_hits)]]));
    hit.addEventListener("mouseleave", hideTip);
    svg.append(hit);
  });
  svg.append(s("line", { class: "axis", x1: L, x2: W - R, y1: base, y2: base }));
  root.append(svg);
  return root;
}
// securityChart draws, per time bucket, how many requests had protected data,
// a threat, a refusal, or a changed answer (OB-3). Counts of requests only.
const SECURITY_SERIES = [
  ["with_data", "s1", "With protected data"], ["threats", "s2", "Threats"],
  ["stopped", "s3", "Blocked or refused"], ["answers_changed", "s4", "Answers changed"],
];
function securityChart(series, bucket) {
  const rows = series.map((d) => ({ ...d, stopped: (d.blocked || 0) + (d.refused || 0) }));
  const root = h("div", {});
  root.append(h("div", { class: "legend" }, ...SECURITY_SERIES.map(([, cls, label]) => h("span", {}, h("span", { class: "sw " + cls }), label))));
  if (!rows.some((d) => SECURITY_SERIES.some(([k]) => d[k] > 0))) {
    root.append(h("p", { class: "empty" }, "Nothing to report in this time range."));
    return root;
  }
  const W = 800, H = 220, L = 44, R = 8, T = 10, B = 28;
  const nice = niceMax(Math.max(1, ...rows.map((d) => Math.max(...SECURITY_SERIES.map(([k]) => d[k] || 0)))));
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img",
    "aria-label": "Requests with protected data, threats, refusals, and changed answers per " + bucket + ". The table below holds the figures per virtual key." });
  for (let i = 0; i <= 4; i++) {
    const y = T + (H - T - B) * (1 - i / 4);
    svg.append(s("line", { class: "grid-line", x1: L, x2: W - R, y1: y, y2: y }));
    const t = s("text", { x: L - 6, y: y + 4, "text-anchor": "end" }); t.textContent = count(Math.round(nice * i / 4)); svg.append(t);
  }
  const n = rows.length, slot = (W - L - R) / n, gap = 1;
  const bw = Math.max(1.5, Math.min(14, (slot - 6) / SECURITY_SERIES.length - gap));
  const base = H - B, yOf = (v) => T + (H - T - B) * (1 - v / nice);
  const labelEvery = Math.ceil(n / 10);
  rows.forEach((d, i) => {
    const x0 = L + slot * i + (slot - SECURITY_SERIES.length * (bw + gap)) / 2;
    SECURITY_SERIES.forEach(([k, cls], j) => {
      const v = d[k] || 0;
      if (v <= 0) return;
      const y = yOf(v);
      svg.append(s("rect", { class: cls, x: x0 + j * (bw + gap), y, width: bw, height: base - y, rx: Math.min(2, bw / 2) }));
    });
    if (i % labelEvery === 0) {
      const t = s("text", { x: L + slot * i + slot / 2, y: H - 8, "text-anchor": "middle" });
      t.textContent = bucket === "hour" ? d.key.slice(11, 16) : d.key.slice(5);
      svg.append(t);
    }
    const hit = s("rect", { class: "hit", x: L + slot * i, y: T, width: slot, height: H - T - B });
    hit.addEventListener("mousemove", (e) => showTip(e, [d.key.replace("T", " "), ["Requests", count(d.requests)],
      ...SECURITY_SERIES.map(([k, , label]) => [label, count(d[k])]), ["Guard unavailable", count(d.guard_unavailable)]]));
    hit.addEventListener("mouseleave", hideTip);
    svg.append(hit);
  });
  svg.append(s("line", { class: "axis", x1: L, x2: W - R, y1: base, y2: base }));
  root.append(svg);
  return root;
}

function niceMax(v) {
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function showTip(e, lines) {
  const tip = document.getElementById("tooltip");
  tip.replaceChildren(h("strong", {}, lines[0]), ...lines.slice(1).map(([k, v]) => h("div", { class: "row" }, h("span", { class: "muted" }, k), h("span", {}, v))));
  tip.hidden = false;
  const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
  tip.style.left = x + "px"; tip.style.top = (e.clientY + 14) + "px";
}
function hideTip() { document.getElementById("tooltip").hidden = true; }

// ---------- views ----------
async function overview() {
  const [sum, ts, models, conns] = await Promise.all([
    api("summary", { range: state.range }), api("timeseries", { range: state.range }),
    api("breakdown", { by: "model", range: state.range }), api("connections"),
  ]);
  const t = sum.totals, p = sum.previous;
  const lookups = t.cache_hits + t.cache_misses;
  const spentPlusAvoided = t.cost_usd + t.cost_avoided_usd;
  return [
    ...setupBanners(),
    h("div", { class: "tiles" },
      tile("Requests", count(t.requests), delta(t.requests, p.requests)),
      tile("Spent", money(t.cost_usd), t.unpriced ? count(t.unpriced) + " unpriced requests" : delta(t.cost_usd, p.cost_usd)),
      tile("Avoided by the cache", money(t.cost_avoided_usd), spentPlusAvoided ? pct(t.cost_avoided_usd, spentPlusAvoided) + " of what you would have spent" : null),
      tile("Cache hit rate", pct(t.cache_hits, lookups), count(t.cache_hits) + " hits of " + count(lookups) + " lookups"),
      tile("Blocked or refused", count(t.blocked + t.refused), count(t.blocked) + " blocked, " + count(t.refused) + " refused"),
      tile("Errors", count(t.errors), "avg " + Math.round(t.avg_ms) + " ms per request")),
    card("Cost per " + (ts.bucket === "hour" ? "hour" : "day"), costChart(ts.series, ts.bucket)),
    semanticCard(t),
    h("div", { class: "grid cols-2" },
      card("Top models", table([
        { label: "Model", get: (r) => h("span", { class: "mono" }, r.key) },
        { label: "Requests", num: true, get: (r) => count(r.requests) },
        { label: "Tokens", num: true, get: (r) => compact(r.input_tokens + r.cached_input_tokens + r.cache_write_tokens + r.output_tokens) },
        { label: "Spent", num: true, get: (r) => money(r.cost_usd) },
        { label: "Avoided", num: true, get: (r) => money(r.cost_avoided_usd) },
      ], models.rows.slice(0, 8))),
      card("Providers", connTable(conns.rows))),
  ];
}

function connTable(rows) {
  if (!rows.length) return h("p", { class: "empty" }, "No provider is configured.");
  const cls = { ok: "good", unused: "", rate_limited: "warning", rejected: "critical", unreachable: "critical", error: "critical" };
  return table([
    { label: "Name", get: (r) => h("span", { class: "mono" }, r.name) },
    { label: "Provider", get: (r) => r.provider + (r.hosting === "local" ? " (local)" : "") },
    { label: "Key", get: (r) => r.key_hint ? h("span", { class: "mono" }, r.key_hint) : h("span", { class: "muted" }, "–") },
    { label: "From", get: (r) => r.source },
    { label: "State", get: (r) => h("span", { class: "pill " + (cls[r.state] || ""), title: r.last_error || "" }, r.state.replace("_", " ")) },
    { label: "Requests", num: true, get: (r) => count(r.requests) },
    { label: "Failures", num: true, get: (r) => count(r.failures) },
  ], rows);
}

async function requests() {
  const params = new URLSearchParams(location.hash.split("/")[1] || "");
  const filter = { outcome: params.get("outcome") || "", cache: params.get("cache") || "" };
  const res = await api("requests", { range: state.range, limit: 200, ...filter });
  const setFilter = (k, v) => { filter[k] = v; const q = new URLSearchParams(Object.entries(filter).filter(([, x]) => x)); location.hash = "requests/" + q; };
  const sel = (k, label, opts) => h("select", { "aria-label": label, onchange: (e) => setFilter(k, e.target.value) },
    opts.map(([v, t]) => h("option", { value: v, selected: filter[k] === v }, t)));
  return [
    card("Recent requests",
      h("div", { class: "filters" },
        sel("outcome", "Outcome", [["", "All outcomes"], ["ok", "OK"], ["blocked", "Blocked"], ["refused", "Refused"], ["error", "Errors"], ["client_error", "Client errors"], ["canceled", "Canceled"]]),
        sel("cache", "Cache", [["", "Any cache result"], ["hit", "Cache hits (exact or semantic)"], ["miss", "Cache misses"], ["bypass", "Bypassed"]])),
      h("p", { class: "muted" }, "Metadata only: KyGate records finding types and counts, never the values or the prompt text. Select a row for details."),
      table([
        { label: "Time", get: (r) => when(r.ts) },
        { label: "Key", get: (r) => r.key_name || "–" },
        { label: "Model", get: (r) => h("span", { class: "mono" }, r.model_served || r.model_requested || "–") },
        { label: "Outcome", get: (r) => outcomePill(r.outcome) },
        { label: "Cache", get: (r) => cachePill(r.cache, r.semantic) },
        { label: "Findings", get: (r) => findingsText(r.findings) },
        { label: "Tokens", num: true, get: (r) => compact(tokens(r)) },
        { label: "Cost", num: true, get: (r) => r.cache === "hit" ? h("span", { title: "avoided" }, "saved " + money(r.cost_avoided_usd)) : (r.unpriced ? "unpriced" : money(r.cost_usd)) },
        { label: "Time", num: true, get: (r) => count(r.total_ms) + " ms" },
      ], res.rows, openRequest)),
  ];
}

function findingsText(f) {
  if (!f || !f.length) return h("span", { class: "muted" }, "–");
  return f.map((x) => x.type.replace("UNREADABLE/", "") + " ×" + x.count + " " + x.action.replace("_", "-") + (x.applied ? "" : " (not applied)")).join(", ");
}

async function openRequest(row) {
  const res = await api("requests/" + encodeURIComponent(row.id));
  const e = res.event;
  const close = () => { back.remove(); drawer.remove(); };
  const back = h("div", { class: "drawer-back", onclick: close });
  const kv = (k, v) => [h("dt", {}, k), h("dd", {}, v === "" || v === undefined || v === null ? "–" : v)];
  const stages = Object.entries(e.stages_us || {}).map(([k, v]) => k + " " + (v / 1000).toFixed(1) + " ms").join(", ");
  const drawer = h("aside", { class: "drawer", role: "dialog", "aria-label": "Request details" },
    h("div", { class: "drawer-head" }, h("h2", {}, "Request " + e.id), h("button", { class: "ghost", onclick: close }, "Close")),
    h("dl", { class: "kv" },
      kv("Time", when(e.ts)), kv("Key", e.key_name), kv("API", e.family + " " + e.endpoint + (e.stream ? " (streamed)" : "")),
      kv("Model requested", e.model_requested), kv("Model served", e.model_served), kv("Provider key", e.connection),
      kv("Outcome", outcomePill(e.outcome)), kv("Reason", e.reason), kv("HTTP status", String(e.status)),
      kv("Cache", h("span", {}, cachePill(e.cache, e.semantic), " ", e.cache_reason || "")),
      kv("Semantic cache", semanticText(e)), kv("Policy", e.mode + ", version " + e.policy_version),
      kv("Findings", findingsText(e.findings)), kv("Near miss", (e.near_miss || []).join(", ")),
      kv("Router (shadow)", e.route_reason ? (e.route_model ? "would use " + e.route_model + (e.route_saving_usd ? ", saving " + money(e.route_saving_usd) : "") + ": " : "stays: ") + e.route_reason : ""), kv("Unreadable content", (e.unreadable || []).join(", ")),
      kv("Tokens", "input " + count(e.input_tokens) + ", cached " + count(e.cached_input_tokens) + ", cache write " + count(e.cache_write_tokens) + ", output " + count(e.output_tokens)),
      kv("Cost", e.unpriced ? "unpriced model" : money(e.cost_usd)), kv("Avoided", money(e.cost_avoided_usd)),
      kv("Duration", count(e.total_ms) + " ms, first byte " + count(e.ttfb_ms) + " ms"), kv("Stages", stages), kv("Attempts", String(e.attempts || 0))),
    res.payload ? [h("h2", { style: null }, "Captured payload (masked)"), h("pre", { class: "payload" }, JSON.stringify(res.payload, null, 2))]
      : h("p", { class: "muted" }, "No payload: the policy does not capture prompt text (audit.capture_payloads: none), or this request was not masked."));
  document.body.append(back, drawer);
  drawer.querySelector("button").focus();
  document.addEventListener("keydown", function esc(ev) { if (ev.key === "Escape") { close(); document.removeEventListener("keydown", esc); } });
}

// levelsText says, for each type the policy needs the Guard for, whether a
// model or only a list finds it.
function levelsText(needs, st, entities) {
  const level = {};
  for (const c of st.coverage || []) level[c.entity_type] = c;
  const types = needs.length ? needs : Object.keys(level);
  if (!types.length) return "–";
  return h("span", {}, types.map((t, i) => {
    const c = level[t];
    const requires = (entities[t] || {}).detection === "model";
    const pill = !c ? h("span", { class: "pill critical" }, "not found")
      : c.level === "model" ? h("span", { class: "pill good", title: c.detectors.join(", ") }, "model")
      : h("span", { class: requires ? "pill critical" : "pill warning", title: "only what is listed is found" }, "list only");
    return [i ? ", " : "", t + " ", pill, requires && (!c || c.level !== "model") ? " (requires a model: refused)" : ""];
  }));
}

// guardCard reports the Guard: whether the policy needs it, whether it answers,
// what it finds, and what happens while it does not answer.
function guardCard(info) {
  const g = info.guard || {};
  const needs = g.needed_for || [];
  const st = g.state;
  const onDown = { block: "requests that need it are refused", local_only: "requests that need it may go to local models only",
    fast_detectors_only: "requests go on with the fast detectors alone, and are flagged" }[g.on_unavailable] || g.on_unavailable;
  const pill = !g.configured ? h("span", { class: "pill" }, "not configured")
    : st.state === "ready" && !needs.length ? h("span", { class: "pill", title: "the policy names none of the types it finds" }, "ready, not used")
    : st.state === "ready" ? h("span", { class: "pill good" }, "ready")
    : st.state === "loading" ? h("span", { class: "pill warning" }, "loading models")
    : h("span", { class: "pill critical" }, "not answering");
  const rows = [
    h("dt", {}, "State"), h("dd", {}, pill, g.configured ? " " + st.addr : ""),
    h("dt", {}, "Needed for"), h("dd", {}, needs.length ? needs.join(", ")
      : g.configured ? "nothing: the Guard runs, and the policy names none of the types it finds. List them with 'kygate policy enable --list', then turn some on with 'kygate policy enable TYPE...' (alert first, then mask)"
      : "nothing: the policy names no ML data type, so the fast detectors are enough"),
    h("dt", {}, "When it does not answer"), h("dd", {}, onDown + " (data.on_guard_unavailable: " + g.on_unavailable + ")"),
  ];
  if (g.configured) {
    rows.push(
      h("dt", {}, "Finds"), h("dd", {}, levelsText(needs, st, info.policy.entities || {})),
      h("dt", {}, "Version"), h("dd", { class: "mono" }, st.version || "–"),
      h("dt", {}, "Calls"), h("dd", {}, count(st.calls) + " calls, " + count(st.failures) + " failures, " + (st.avg_ms || 0).toFixed(1) + " ms on average"),
      h("dt", {}, "Last error"), h("dd", {}, st.last_error ? st.last_error + " (" + when(st.last_error_at) + ")" : "–"));
  }
  if (g.memo) rows.push(h("dt", {}, "Findings memo"), h("dd", {}, count(g.memo.segments) + " segments remembered, " + count(g.memo.hits) + " answered without asking the Guard"));
  const warn = needs.length && (!g.configured || st.state !== "ready")
    ? h("div", { class: "banner warn" }, h("strong", {}, "The Guard is needed and not ready"), "The policy names " + needs.join(", ") + ", which only the Guard finds. Until it answers, " + onDown + ".")
    : null;
  return card("Guard (ML detection)", warn, h("dl", { class: "kv" }, rows));
}

async function protection() {
  const [f, sum, sec] = await Promise.all([api("findings", { range: state.range }), api("summary", { range: state.range }), api("security", { range: state.range })]);
  const rows = f.rows;
  const isOutput = (r) => r.type.startsWith("OUTPUT_");
  const total = rows.filter((r) => r.type !== "PROMPT_INJECTION" && !isOutput(r)).reduce((a, r) => a + r.count, 0);
  const answersChanged = rows.filter((r) => isOutput(r) && r.applied && r.action !== "alert").reduce((a, r) => a + r.requests, 0);
  const notApplied = rows.filter((r) => !r.applied).reduce((a, r) => a + r.count, 0);
  const injections = rows.filter((r) => r.type === "PROMPT_INJECTION").reduce((a, r) => a + r.requests, 0);
  const pol = state.info.policy;
  const threats = Object.entries(pol.threats || {});
  return [
    ...setupBanners(),
    h("div", { class: "tiles" },
      tile("Values found", count(total), "by the fast detectors"),
      tile("Requests blocked", count(sum.totals.blocked), "a blocked type was present"),
      tile("Requests refused", count(sum.totals.refused), "local-only data, external model"),
      tile("Recorded only", count(notApplied), pol.mode === "monitor" ? "monitor mode: nothing was changed" : "in monitor mode or refused requests"),
      tile("Alerts", count(sum.totals.alerts), "alert actions"),
      tile("Injection attempts", threats.length ? count(injections) : "–", threats.length ? "requests flagged by the Guard" : "not in the policy"),
      tile("Answers changed", pol.output_on ? count(answersChanged) : "–", pol.output_on ? "output inspection removed or blocked something" : "output inspection is off")),
    card("Security over time", h("p", { class: "muted" }, "Requests per " + sec.bucket + ". A request counts once in each column, whatever the number of values in it."),
      securityChart(sec.series, sec.bucket)),
    card("Main sources", h("p", { class: "muted" }, "Per virtual key: the requests that carried protected data or a threat, were stopped, or got a changed answer."),
      table([
        { label: "Virtual key", get: (r) => h("span", { class: "mono" }, r.key) },
        { label: "Requests", num: true, get: (r) => count(r.requests) },
        { label: "Protected data", num: true, get: (r) => count(r.with_data) },
        { label: "Threats", num: true, get: (r) => count(r.threats) },
        { label: "Blocked", num: true, get: (r) => count(r.blocked) },
        { label: "Refused", num: true, get: (r) => count(r.refused) },
        { label: "Answers changed", num: true, get: (r) => count(r.answers_changed) },
        { label: "Alerts", num: true, get: (r) => count(r.alerts) },
        { label: "Guard unavailable", num: true, get: (r) => count(r.guard_unavailable) },
      ], sec.sources)),
    guardCard(state.info),
    card("Findings by data type", h("p", { class: "muted" }, "Counts of values, never the values. Types such as PERSON come from the Guard; SECRET, CREDIT_CARD, IBAN, and EMAIL from the fast detectors; OUTPUT_ types are found in answers by output inspection."),
      table([
        { label: "Data type", get: (r) => h("span", { class: "mono" }, r.type) },
        { label: "Action", get: (r) => r.action.replace("_", "-") },
        { label: "Applied", get: (r) => r.applied ? h("span", { class: "pill good" }, "✓ applied") : h("span", { class: "pill warning" }, "recorded only") },
        { label: "Values", num: true, get: (r) => count(r.count) },
        { label: "Requests", num: true, get: (r) => count(r.requests) },
      ], rows)),
    card("Policy in force",
      h("dl", { class: "kv" },
        h("dt", {}, "File"), h("dd", { class: "mono" }, pol.path),
        h("dt", {}, "Mode"), h("dd", {}, pol.mode),
        h("dt", {}, "Images, files, audio"), h("dd", {}, pol.unreadable_content.replace("_", "-")),
        h("dt", {}, "Embeddings with protected data"), h("dd", {}, pol.embeddings.replace("_", "-")),
        h("dt", {}, "Payload capture"), h("dd", {}, pol.capture_payloads)),
      table([
        { label: "Data type", get: (r) => h("span", { class: "mono" }, r[0]) },
        { label: "Action", get: (r) => r[1].action.replace("_", "-") },
      ], Object.entries(pol.entities || {})),
      threats.length ? table([
        { label: "Threat", get: (r) => h("span", { class: "mono" }, r[0].toUpperCase()) },
        { label: "Action", get: (r) => r[1].action },
        { label: "From score", num: true, get: (r) => (r[1].min_score || 0).toFixed(2) },
        { label: "Scanned in", get: (r) => (r[1].segments || []).join(", ").replace("_", " ") },
      ], threats) : h("p", { class: "muted" }, "No threats in the policy. Turn prompt-injection detection on with 'kygate policy enable PROMPT_INJECTION' (needs the Guard and its prompt-injection pack)."),
      pol.output_on ? table([
        { label: "Output check", get: (r) => r[0] },
        { label: "Action", get: (r) => (r[1] && r[1].action) || "off" },
      ], [["Secrets in answers", pol.output.secrets], ["Images from unknown sites", pol.output.images],
          ["Addresses carrying protected data", pol.output.protected_urls], ["Links to unknown sites", pol.output.links],
          ["Known sites", { action: (pol.output.allowed_domains || []).join(", ") || "only those named in the request" }]])
        : h("p", { class: "muted" }, "Output inspection is off: the policy has no output: section. See the starter policy for one.")),
  ];
}

function limitText(l) {
  if (!l || (!l.soft && !l.hard)) return "";
  return " of " + [l.soft ? "soft " + money(l.soft) : "", l.hard ? "hard " + money(l.hard) : ""].filter(Boolean).join(", ");
}

async function usage() {
  const [byKey, byModel, byConn, byEndpoint, byTeam, byProject, byUser] = await Promise.all(["key", "model", "connection", "endpoint", "team", "project", "user"].map((by) => api("breakdown", { by, range: state.range })));
  const people = byUser.rows.filter((r) => r.key !== "(no user)");
  const hierarchy = byTeam.rows.some((r) => r.key !== "(no team)") || byProject.rows.some((r) => r.key !== "(no project)");
  const near = await api("nearmiss", { range: state.range });
  const route = await api("routing", { range: state.range });
  const bud = await api("budgets");
  const quality = await api("quality", { range: state.range }).catch(() => null);
  const moved = route.rows.filter((r) => r.would);
  const decided = route.rows.reduce((a, r) => a + r.requests, 0);
  const wouldMove = moved.reduce((a, r) => a + r.requests, 0);
  const saving = moved.reduce((a, r) => a + r.saving_usd, 0);
  const cols = (label) => [
    { label, get: (r) => h("span", { class: "mono" }, r.key) },
    { label: "Requests", num: true, get: (r) => count(r.requests) },
    { label: "Input", num: true, get: (r) => compact(r.input_tokens) },
    { label: "Cached input", num: true, get: (r) => compact(r.cached_input_tokens) },
    { label: "Output", num: true, get: (r) => compact(r.output_tokens) },
    { label: "Spent", num: true, get: (r) => money(r.cost_usd) },
    { label: "Avoided", num: true, get: (r) => money(r.cost_avoided_usd) },
    { label: "Hit rate", num: true, get: (r) => pct(r.cache_hits, r.cache_hits + r.cache_misses) },
  ];
  return [
    qualityCard(quality),
    card("By virtual key", table(cols("Key"), byKey.rows)),
    hierarchy ? h("div", { class: "grid cols-2" },
      card("By team", table(cols("Team").slice(0, 6), byTeam.rows)),
      card("By project", table(cols("Project").slice(0, 6), byProject.rows))) : null,
    people.length ? userCard(cols, byUser.rows) : null,
    card("Budgets", !bud.on
      ? h("p", { class: "muted" }, "No budget in the policy. budgets: sets monthly and daily limits in US dollars for the organization, for every key (per_key), for each person named by a user token (per_user), and for named keys (keys); past a soft limit new conversations go one tier down, past a hard limit requests are refused. Cache hits cost nothing.")
      : [h("p", { class: "muted" }, "Spend this month and today (UTC), reservations in flight included, against the soft and hard limits. Past a soft limit: " + (bud.at_soft === "cheaper_tier" ? "new conversations go one tier down within their provider" : "flagged only") + ". Past a hard limit: refused (429)."),
        table([
          { label: "Budget", get: (r) => r.scope === "org" ? h("strong", {}, "Organization") : [h("span", { class: "muted" }, r.scope + " "), h("span", { class: "mono" }, r.name)] },
          { label: "This month", num: true, get: (r) => money(r.monthly_usd) + limitText(r.limits.monthly_usd) },
          { label: "Today", num: true, get: (r) => money(r.daily_usd) + limitText(r.limits.daily_usd) },
          { label: "State", get: (r) => h("span", { class: "pill " + ({ ok: "good", soft: "warning", hard: "critical" }[r.state] || "") }, { ok: "within limits", soft: "past soft limit", hard: "past hard limit" }[r.state]) },
        ], bud.rows)]),
    card("Routing (shadow mode)", route.mode !== "shadow" && !decided
      ? h("p", { class: "muted" }, "The router is off. Set routing: { mode: shadow } in the policy: it records the cheaper model it would use for each request, and what that would save, and changes nothing.")
      : [h("p", { class: "muted" }, "What the router would do: one tier down, within the same provider, for short plain prompts at the start of a conversation. Nothing is changed: every request still goes to the model it names. The saving prices the real tokens at the cheaper model."),
        h("div", { class: "tiles" },
          tile("Requests decided", count(decided), "chat and messages requests that reached a model"),
          tile("Would move", pct(wouldMove, decided), count(wouldMove) + " requests"),
          tile("Estimated saving", money(saving), "if those had gone to the cheaper model")),
        table([
          { label: "Requested", get: (r) => h("span", { class: "mono" }, r.requested) },
          { label: "Would use", get: (r) => r.would ? h("span", { class: "mono" }, r.would) : "stays" },
          { label: "Why", get: (r) => r.reason },
          { label: "Requests", num: true, get: (r) => count(r.requests) },
          { label: "Spent", num: true, get: (r) => money(r.cost_usd) },
          { label: "Would save", num: true, get: (r) => r.would ? money(r.saving_usd) : "–" },
        ], route.rows)]),
    card("Why the exact cache missed", h("p", { class: "muted" },
      "Misses where the same key asked the same question again, and something else in the request had changed: a date in the system prompt, a cursor position, a setting. The cost is what those requests cost: what removing the difference from the fingerprint could save. A measurement; it changes nothing."),
      near.rows.length ? table([
        { label: "What changed", get: (r) => h("span", { class: "mono" }, r.label) },
        { label: "Misses", num: true, get: (r) => count(r.requests) },
        { label: "Keys", num: true, get: (r) => count(r.keys) },
        { label: "Cost of those misses", num: true, get: (r) => money(r.cost_usd) },
      ], near.rows) : h("p", { class: "empty" }, "No near misses in this time range.")),
    card("By model", table(cols("Model"), byModel.rows)),
    h("div", { class: "grid cols-2" },
      card("By provider key", table(cols("Provider key").slice(0, 6), byConn.rows)),
      card("By API", table(cols("API").slice(0, 6), byEndpoint.rows))),
  ];
}

// Quality signals (OB-4): what applications say about answers, by how each was
// served, and the semantic cache's shadow comparisons.
function qualityCard(q) {
  if (!q) return null;
  const by = (pred) => q.rows.filter(pred).reduce((a, r) => a + r.count, 0);
  const rated = by(() => true);
  const bad = (pred) => by((r) => r.rating === "bad" && pred(r));
  const all = (pred) => by(pred);
  const rate = (pred) => all(pred) ? pct(bad(pred), all(pred)) + " bad of " + count(all(pred)) : "no rating";
  const reasons = {};
  q.rows.filter((r) => r.rating === "bad").forEach((r) => { reasons[r.reason || "(none)"] = (reasons[r.reason || "(none)"] || 0) + r.count; });
  const s = q.semantic;
  return card("Answer quality",
    h("p", { class: "muted" }, "Applications rate answers with POST /kygate/v1/feedback and the answer's X-KyGate-Request-Id, using the key that made the request: \"bad\" or \"good\", with a reason code, never text. Compare answers served from the caches with those from the model, and those the router would have sent to a cheaper model."),
    h("div", { class: "tiles" },
      tile("Ratings", count(rated), rated ? pct(bad(() => true), rated) + " bad" : "none yet"),
      tile("From the model", rate((r) => r.served === "model"), ""),
      tile("Exact-cache hits", rate((r) => r.served === "exact"), ""),
      tile("Semantic-cache hits", rate((r) => r.served === "semantic"), "a bad rating here is a likely false hit"),
      tile("Router would move", rate((r) => r.routable), "answers the router would have sent to a cheaper model"),
      tile("Semantic shadow", s.agree + s.disagree ? pct(s.disagree, s.agree + s.disagree) + " differed" : "–", s.agree + s.disagree ? count(s.agree + s.disagree) + " compared with the real answer" : "no comparison yet")),
    Object.keys(reasons).length ? h("p", {}, "Reasons for bad ratings: " + Object.entries(reasons).sort((a, b) => b[1] - a[1]).map(([k, v]) => k.replace("_", " ") + " " + count(v)).join(", ")) : null,
    q.rows.length ? table([
      { label: "Served", get: (r) => r.served === "model" ? "model" : r.served + " cache" },
      { label: "Model", get: (r) => h("span", { class: "mono" }, r.model || "–") },
      { label: "Router would move", get: (r) => r.routable ? "yes" : "no" },
      { label: "Rating", get: (r) => h("span", { class: "pill " + (r.rating === "bad" ? "critical" : "good") }, r.rating) },
      { label: "Reason", get: (r) => r.reason ? r.reason.replace("_", " ") : "–" },
      { label: "Count", num: true, get: (r) => count(r.count) },
    ], q.rows) : null);
}

// The fleet: every KyGate process and what it sees, from heartbeats.
function fleetCard(f) {
  if (!f || !f.rows) return null;
  const pill = (txt, c) => h("span", { class: "pill " + c }, txt);
  const lag = (s) => {
    if (!s) return "–";
    const waiting = s.bytes > 0 ? compact(s.bytes) + "B waiting" : "nothing waiting";
    const err = s.last_error && (!s.last_delivery || s.last_error_at > s.last_delivery) ? pill("failing", "critical") : null;
    return h("span", { title: s.last_error || "" }, waiting + (s.dropped ? ", " + count(s.dropped) + " dropped" : "") + (s.last_delivery ? ", delivered " + when(s.last_delivery) : ""), err ? " " : "", err);
  };
  const guard = (g) => !g ? h("span", { class: "muted" }, "not configured") : pill(g.state + (g.calls ? ", " + g.avg_ms.toFixed(0) + " ms" : ""), g.state === "ready" ? "good" : g.state === "loading" ? "warning" : "critical");
  const provs = (p) => {
    if (!p || !p.length) return "–";
    const bad = p.filter((x) => ["rejected", "unreachable", "error", "rate_limited"].includes(x.state));
    return bad.length ? pill(bad.map((x) => x.name + " " + x.state.replace("_", " ")).join(", "), "warning") : pill(p.length + " ok", "good");
  };
  const roleOf = (m) => m.role === "all" ? "gateway and control" : m.role;
  return card("Fleet",
    h("p", { class: "muted" }, "Every KyGate process writes what it sees every 10 seconds. One not heard from for " + f.silent_after_s + " seconds is silent: stopped without leaving, or cut off from the database."),
    f.rows.length ? table([
      { label: "Process", get: (m) => h("span", {}, roleOf(m), " ", h("span", { class: "mono muted" }, m.host)) },
      { label: "State", get: (m) => m.status === "up" ? pill("up", "good") : h("span", {}, pill("silent", "critical"), " since " + when(m.seen)) },
      { label: "Version", get: (m) => m.version },
      { label: "Started", get: (m) => when(m.started) },
      { label: "In flight", num: true, get: (m) => m.state ? count(m.state.in_flight) : "–" },
      { label: "Events", get: (m) => lag(m.state && m.state.spool) },
      { label: "Guard", get: (m) => guard(m.state && m.state.guard) },
      { label: "Counters", get: (m) => !m.state ? "–" : m.state.counters + (m.state.counters_degraded ? " (" + count(m.state.counters_degraded) + " from last known figures)" : "") },
      { label: "Cache", get: (m) => !m.state ? "–" : m.state.cache + (m.state.cache_errors ? " (" + count(m.state.cache_errors) + " errors)" : "") },
      { label: "Providers", get: (m) => provs(m.state && m.state.providers) },
    ], f.rows) : h("p", { class: "empty" }, "No heartbeat yet."));
}

async function setup() {
  const [conns, keys, fleet] = await Promise.all([api("connections"), api("keys"), api("fleet").catch(() => null)]);
  const i = state.info;
  const base = i.model_api;
  return [
    ...setupBanners(),
    fleetCard(fleet),
    card("Connect a client",
      h("p", {}, "Change two settings in your application: the base URL, and the API key, which becomes a KyGate virtual key."),
      h("dl", { class: "kv" },
        h("dt", {}, "OpenAI SDKs"), h("dd", { class: "mono" }, "base_url = " + base + "/v1"),
        h("dt", {}, "Anthropic SDKs"), h("dd", { class: "mono" }, "base_url = " + base),
        h("dt", {}, "API key"), h("dd", { class: "mono" }, "a virtual key: kg-…  (kygate key create NAME)"))),
    card("Provider keys", h("p", { class: "muted" }, "Keys are never shown. Add one with environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, KYGATE_LOCAL_<NAME>) or 'kygate provider add'."), connTable(conns.rows)),
    card("Virtual keys", table([
      { label: "Name", get: (r) => r.name },
      { label: "ID", get: (r) => h("span", { class: "mono" }, r.id) },
      { label: "Starts with", get: (r) => h("span", { class: "mono" }, r.prefix + "…") },
      { label: "Created", get: (r) => when(r.created_at) },
      { label: "State", get: (r) => r.revoked_at ? h("span", { class: "pill critical" }, "revoked") : h("span", { class: "pill good" }, "active") },
    ], keys.rows)),
    card("Installation", h("dl", { class: "kv" },
      h("dt", {}, "Version"), h("dd", {}, i.version + " (" + i.profile + ")"),
      h("dt", {}, "Organization"), h("dd", { class: "mono" }, i.org_id),
      h("dt", {}, "Cache"), h("dd", {}, count(i.cache.entries) + " entries in memory, " + compact(i.cache.bytes) + "B, scope " + i.policy.cache_scope + ", TTL " + i.policy.cache_ttl),
      h("dt", {}, "Cache file"), h("dd", {}, cacheFile(i.cache.disk)),
      h("dt", {}, "Regenerate rule"), h("dd", {}, i.policy.cache_repeat_window === "0s" ? "off: every repeat is answered from the cache" : "a repeat within " + i.policy.cache_repeat_window + " gets a fresh answer"),
      h("dt", {}, "Semantic cache"), h("dd", {}, semanticSetup(i)),
      h("dt", {}, "Guard"), h("dd", {}, !i.guard || !i.guard.configured ? "not configured (optional)"
      : i.guard.state.addr + ", " + i.guard.state.state + ((i.guard.needed_for || []).length ? "" : ", not used by the policy")),
      h("dt", {}, "Event spool"), h("dd", {}, compact(i.spool_bytes) + "B waiting for delivery"),
      h("dt", {}, "Retention"), h("dd", {}, i.policy.retention_days + " days"),
      h("dt", {}, "Metrics"), h("dd", { class: "mono" }, location.origin + "/metrics"))),
  ];
}

start();

// ---------- administration ----------
// What each role may change; the server checks again on every request.
const CAN = {
  teams: ["admin"], projects: ["admin", "team_lead"], keys: ["admin", "team_lead"],
  users: ["admin"], providers: ["admin"], policies: ["admin", "security", "finance", "team_lead"], audit: ["admin", "security"],
  data: ["admin", "security"],
};
function can(what) { return CAN[what].includes(state.me.role); }
function statusLine() { return h("p", { class: "status", hidden: true }); }
function say(el, ok, msg) { el.hidden = false; el.className = "status " + (ok ? "ok" : "err"); el.textContent = msg; }
function field(label, attrs) { return h("label", {}, label, h("input", attrs)); }
function choice(label, name, options) {
  return h("label", {}, label, h("select", { name }, ...options.map((o) => h("option", { value: o }, o || "(none)"))));
}
function form(fields, submit, onSubmit) {
  const st = statusLine();
  const f = h("form", { class: "admin-form" }, ...fields, h("button", { type: "submit" }, submit));
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(f).entries());
    try { const msg = await onSubmit(data, f); say(st, true, msg || "Done."); }
    catch (err) { if (err.message !== "unauthorized") say(st, false, err.message); }
  });
  return [f, st];
}
function dangerButton(label, confirmText, run) {
  const b = h("button", { class: "small danger", type: "button" }, label);
  b.addEventListener("click", async () => {
    if (!confirm(confirmText)) return;
    try { await run(); route(); } catch (err) { if (err.message !== "unauthorized") alert(err.message); }
  });
  return b;
}

async function admin() {
  const role = state.me.role;
  const hier = await api("admin/hierarchy");
  const teamName = Object.fromEntries(hier.teams.map((t) => [t.id, t.name]));
  const projName = Object.fromEntries(hier.projects.map((p) => [p.id, p.name]));
  const out = [h("p", { class: "muted" }, "Signed in as " + state.me.actor + ", role " + role.replace("_", " ") +
    (state.me.team ? " of team " + state.me.team : "") + ". Every change here is recorded in the audit trail.")];

  // Teams
  out.push(card("Teams",
    table([
      { label: "Team", get: (t) => h("span", { class: "mono" }, t.name) },
      { label: "Projects", get: (t) => hier.projects.filter((p) => p.team_id === t.id).map((p) => p.name).join(", ") || "–" },
      { label: "", get: (t) => can("teams") ? dangerButton("Delete", "Delete team " + t.name + "?", () => apiWrite("DELETE", "admin/teams/" + encodeURIComponent(t.name))) : "" },
    ], hier.teams),
    ...(can("teams") ? form([field("New team", { name: "name", required: true, placeholder: "finance" })], "Create team",
      async (d) => { await apiWrite("POST", "admin/teams", { name: d.name }); setTimeout(route, 600); return "Team " + d.name + " created."; }) : [])));

  // Projects
  const teamChoices = role === "team_lead" ? [state.me.team] : ["", ...hier.teams.map((t) => t.name)];
  out.push(card("Projects",
    table([
      { label: "Project", get: (p) => h("span", { class: "mono" }, p.name) },
      { label: "Team", get: (p) => teamName[p.team_id] || "(none)" },
      { label: "Active keys", num: true, get: (p) => count(hier.keys.filter((k) => k.project_id === p.id && !k.revoked_at).length) },
      { label: "", get: (p) => can("projects") ? dangerButton("Delete", "Delete project " + p.name + "?", () => apiWrite("DELETE", "admin/projects/" + encodeURIComponent(p.name))) : "" },
    ], hier.projects),
    ...(can("projects") ? form([field("New project", { name: "name", required: true, placeholder: "ledger" }), choice("Team", "team", teamChoices)], "Create project",
      async (d) => { await apiWrite("POST", "admin/projects", { name: d.name, team: d.team || "" }); setTimeout(route, 600); return "Project " + d.name + " created."; }) : [])));

  // Virtual keys
  const projectChoices = role === "team_lead" ? hier.projects.map((p) => p.name) : ["", ...hier.projects.map((p) => p.name)];
  const keyCard = card("Virtual keys",
    table([
      { label: "Key", get: (k) => h("span", { class: "mono" }, k.name) },
      { label: "Prefix", get: (k) => h("span", { class: "mono" }, k.prefix + "…") },
      { label: "Project", get: (k) => projName[k.project_id] || "(none)" },
      { label: "State", get: (k) => k.revoked_at ? h("span", { class: "pill" }, "revoked") : h("span", { class: "pill good" }, "active") },
      { label: "User tokens", get: (k) => k.revoked_at ? "" : (k.require_user ? "required" : "optional") + (k.user_tokens ? ", secret set" : "") },
      { label: "", get: (k) => can("keys") && !k.revoked_at ? userKeyActions(k) : "" },
      { label: "", get: (k) => can("keys") && !k.revoked_at ? dangerButton("Revoke", "Revoke key " + k.name + "? Clients using it stop working within seconds.", () => apiWrite("POST", "admin/keys/" + encodeURIComponent(k.name) + "/revoke")) : "" },
    ], hier.keys));
  if (can("keys") && projectChoices.length) {
    const once = h("div");
    const [f, st] = form([field("New key", { name: "name", required: true, placeholder: "ledger-app" }), choice("Project", "project", projectChoices)], "Create key",
      async (d) => {
        const r = await apiWrite("POST", "admin/keys", { name: d.name, project: d.project || "" });
        once.replaceChildren(h("div", { class: "banner warn" }, h("strong", {}, "Copy this key now: it is shown once"), h("div", { class: "secret-once" }, r.key)));
        return "Key " + d.name + " created.";
      });
    keyCard.append(f, st, once);
  }
  out.push(keyCard);

  // People
  if (can("users") && !isEnterprise()) {
    out.push(enterpriseCard("People who sign in",
      "Single sign-on, the five roles, and SCIM provisioning are part of KyGate Enterprise. This Community edition opens the console and the admin API with the admin token."));
  } else if (can("users")) {
    const users = await api("admin/users");
    out.push(card("People who sign in",
      h("p", { class: "muted" }, "With single sign-on, a person on this list signs in with this role; others may still come in through the group mapping in sso.yaml. A change ends their current sessions."),
      table([
        { label: "Email", get: (u) => u.email },
        { label: "Role", get: (u) => u.role.replace("_", " ") },
        { label: "Team", get: (u) => teamName[u.team_id] || "–" },
        { label: "Last sign-in", get: (u) => u.last_login ? when(u.last_login) : "never" },
        { label: "", get: (u) => dangerButton("Remove", "Remove " + u.email + "?", () => apiWrite("DELETE", "admin/users/" + encodeURIComponent(u.email))) },
      ], users.rows),
      ...form([field("Email", { name: "email", type: "email", required: true, placeholder: "ana@example.com" }),
        choice("Role", "role", ["viewer", "team_lead", "finance", "security", "admin"]), choice("Team (team lead)", "team", ["", ...hier.teams.map((t) => t.name)])],
      "Add or change", async (d) => { await apiWrite("PUT", "admin/users/" + encodeURIComponent(d.email.toLowerCase()), { role: d.role, team: d.team || "" }); setTimeout(route, 600); return d.email + " is " + d.role + "."; })));
    // SCIM (GV-2): people and groups your identity provider manages.
    const prov = users.provisioned || [];
    out.push(card("Provisioned by your identity provider (SCIM)",
      h("p", { class: "muted" }, users.scim
        ? "Your identity provider adds, changes, and removes these people through SCIM. Their role comes from their groups, through the groups mapping in sso.yaml; the list above comes first. A deactivated person cannot sign in, even if the list above names them."
        : "SCIM is off. 'kygate scim token' turns it on and prints the token your identity provider needs."),
      prov.length ? table([
        { label: "Email", get: (u) => u.email },
        { label: "State", get: (u) => u.active ? "active" : "deactivated" },
        { label: "Groups", get: (u) => u.groups.length ? u.groups.join(", ") : "–" },
        { label: "Role from groups", get: (u) => u.role ? u.role.replace("_", " ") + (u.team ? " of " + u.team : "") : "none" },
        { label: "On the list above", get: (u) => u.listed ? "yes: the list's role applies" : "no" },
        { label: "Changed", get: (u) => when(u.updated) },
      ], prov) : (users.scim ? h("p", { class: "muted" }, "Nobody provisioned yet.") : null)));
  }

  // Provider keys
  if (can("providers")) {
    const conns = await api("connections");
    out.push(card("Provider keys",
      h("p", { class: "muted" }, "A provider key is stored sealed under the master key and is never shown again, here or anywhere."),
      table([
        { label: "Name", get: (c) => h("span", { class: "mono" }, c.name) },
        { label: "Provider", get: (c) => c.provider },
        { label: "Source", get: (c) => c.source || "" },
        { label: "Region", get: (c) => c.region || "–" },
        { label: "", get: (c) => c.source === "stored" ? dangerButton("Delete", "Delete provider key " + c.name + "?", () => apiWrite("DELETE", "admin/providers/" + encodeURIComponent(c.name))) : "" },
      ], conns.rows || []),
      ...form([field("Name", { name: "name", required: true, placeholder: "openai-team" }), choice("Provider", "provider", ["openai", "anthropic", "local"]),
        field("Base URL (local)", { name: "base_url", placeholder: "http://localhost:11434/v1" }), field("Region", { name: "region", placeholder: "eu" }),
        field("Key", { name: "key", type: "password", autocomplete: "off" })],
      "Store", async (d, f) => { await apiWrite("POST", "admin/providers", d); f.reset(); setTimeout(route, 2500); return "Stored; KyGate uses it within seconds."; })));
  }

  // Policies
  if (can("policies")) {
    const pols = await api("admin/policies");
    const editor = h("textarea", { class: "policy", spellcheck: "false" });
    const idInput = h("input", { placeholder: "org, team-NAME, project-NAME, key-NAME", value: "org" });
    const st = statusLine();
    const load = async (id) => {
      idInput.value = id;
      const res = await fetch("/api/v1/admin/policies/" + encodeURIComponent(id), { credentials: "same-origin" });
      editor.value = res.ok ? await res.text() : "# a new file: write only what this level changes\n";
      say(st, true, res.ok ? "Loaded " + id + "." : "No file " + id + " yet: saving creates it.");
    };
    const save = h("button", { type: "button" }, "Validate and save");
    save.addEventListener("click", async () => {
      try {
        const r = await apiWrite("PUT", "admin/policies/" + encodeURIComponent(idInput.value.trim()), editor.value, true);
        say(st, true, "Saved " + r.path + (r.warnings.length ? ". Notes: " + r.warnings.join("; ") : ". KyGate uses it within seconds."));
      } catch (err) { if (err.message !== "unauthorized") say(st, false, err.message); }
    });
    const limits = { security: "mode, data, threats, output", finance: "budgets, rate_limits", team_lead: "the files of your team and its projects, except budgets and rate limits" }[role];
    out.push(card("Policy files",
      h("p", { class: "muted" }, "Each file is validated before it is saved; the previous version is kept as .bak." + (limits ? " Your role may change: " + limits + "." : "")),
      h("div", { class: "admin-form" }, ...pols.rows.map((p) => { const b = h("button", { class: "small ghost", type: "button" }, p.id); b.addEventListener("click", () => load(p.id)); return b; })),
      h("div", { class: "admin-form" }, h("label", {}, "File", idInput), save), editor, st));
    load("org").catch(() => {});
  }

  // Data handling (GV-4): retention, region pinning, purges
  if (can("data")) out.push(await dataCard());

  // Audit integrity and SIEM export (GV-3)
  if (can("audit")) out.push(await integrityCard());

  // Audit trail
  if (can("audit")) {
    const log = await api("admin/log");
    out.push(card("Audit trail", table([
      { label: "When", get: (a) => when(a.ts) },
      { label: "Who", get: (a) => a.actor },
      { label: "What", get: (a) => h("span", { class: "mono" }, a.action) },
      { label: "On", get: (a) => a.target },
      { label: "Detail", get: (a) => a.detail || "" },
    ], log.rows)));
  }
  return out;
}

// ---------- data handling (GV-4) ----------
function dayStart(v) { return v ? v + "T00:00:00Z" : undefined; }

async function dataCard() {
  const d = await api("admin/data");
  const r = d.retention;
  const pinned = d.regions && d.regions.length;
  const parts = [
    h("p", { class: "muted" }, "Retention runs once an hour in the control process. Change the periods in the organization's policy file (audit:), and the regions under data.regions."),
    table([{ label: "Kept", get: (x) => x[0] }, { label: "For", get: (x) => x[1] }], [
      ["Usage and audit events", r.events_days + " days"],
      ["Captured payloads (masked)", r.capture === "none" ? "not captured" : r.payloads_days + " days"],
      ["Administration trail", r.admin_days ? r.admin_days + " days" : "kept"],
    ]),
    h("h3", {}, "Regions"),
    h("p", { class: "muted" }, pinned
      ? "Requests go only to connections in: " + d.regions.join(", ") + (d.mode === "monitor" ? " (monitor mode: recorded, not enforced)." : ". A connection without a region is not used.")
      : "No pinning: requests may go to any connection. Set data.regions in a policy to pin them."),
    table([
      { label: "Connection", get: (c) => h("span", { class: "mono" }, c.name) },
      { label: "Region", get: (c) => c.region || "–" },
      { label: "Used", get: (c) => !pinned ? "yes" : c.allowed ? h("span", { class: "pill good" }, "yes") : h("span", { class: "pill" }, "no") },
      { label: "Set by", get: (c) => c.source === "env" ? h("span", { class: "mono" }, c.variable) : "below, or 'kygate provider region'" },
    ], d.connections || []),
  ];
  const stored = (d.connections || []).filter((c) => c.source === "stored").map((c) => c.name);
  if (stored.length) {
    parts.push(...form([choice("Stored connection", "name", stored), field("Region (empty clears)", { name: "region", placeholder: "eu" })], "Set region",
      async (x) => { await apiWrite("PUT", "admin/providers/" + encodeURIComponent(x.name) + "/region", { region: x.region }); setTimeout(route, 2500); return x.name + ": region " + (x.region || "cleared") + "."; }));
  }

  // Purge events: count first, then confirm.
  parts.push(h("h3", {}, "Purge events"),
    h("p", { class: "muted" }, "Deleted events leave the reports and the budget counters rebuilt at the next start. \"Payloads only\" keeps the events and deletes the captured masked text."));
  parts.push(...form([
    field("Key", { name: "key", placeholder: "name" }), field("Team", { name: "team" }), field("Project", { name: "project" }),
    field("Person", { name: "user", placeholder: "ID or email" }),
    field("From", { name: "from", type: "date" }), field("Before", { name: "to", type: "date" }),
    choice("What", "what", ["events", "payloads only"]),
  ], "Count, then purge", async (x) => {
    const body = { key: x.key || undefined, team: x.team || undefined, project: x.project || undefined, user: x.user || undefined, from: dayStart(x.from), to: dayStart(x.to), payloads_only: x.what === "payloads only" };
    const dry = await apiWrite("POST", "admin/purge/events", { ...body, dry_run: true });
    if (!dry.matched) return "Nothing matches.";
    if (!confirm("Delete " + dry.matched + (body.payloads_only ? " captured payloads" : " events") + "? This cannot be undone.")) return "Nothing was deleted.";
    const res = await apiWrite("POST", "admin/purge/events", body);
    return "Deleted " + res.deleted + ".";
  }));

  // Purge the cache
  if (d.purges) {
    parts.push(h("h3", {}, "Purge the cache"),
      h("p", { class: "muted" }, "Removes answers from the exact and semantic caches of every KyGate process within seconds. Applications tag answers with the X-KyGate-Cache-Tags header."));
    parts.push(...form([choice("By", "by", ["tag", "key", "all"]), field("Tag or key name", { name: "value" })], "Purge", async (x) => {
      const body = x.by === "all" ? { all: true } : { [x.by]: x.value };
      if (!confirm(x.by === "all" ? "Delete every cached answer?" : "Delete the cached answers of " + x.by + " " + x.value + "?")) return "Nothing was deleted.";
      const res = await apiWrite("POST", "admin/purge/cache", body);
      return "Deleted " + res.exact + " exact and " + res.semantic + " semantic entries here; the other processes follow.";
    }));
  }
  return card("Data handling", ...parts);
}

// ---------- end-user identity (AC-3) ----------
// People appear by pseudonym (u_...): KyGate never stores their IDs. The
// lookup turns an ID into its pseudonym on the server and highlights the row.
function userCard(cols, rows) {
  const box = h("div");
  const draw = (mark) => box.replaceChildren(table(cols("Person").slice(0, 6).map((c, i) => i ? c : { label: "Person", get: (r) => h("span", { class: "mono" + (r.key === mark ? " hl" : "") }, r.key === mark ? r.key + "  ← found" : r.key) }), rows.slice(0, 50)));
  draw("");
  const [f, st] = form([field("Find a person", { name: "id", required: true, placeholder: "ID or email, as the user token names it" })], "Find", async (x) => {
    const r = await apiWrite("POST", "users/pseudonym", { id: x.id });
    draw(r.user);
    return rows.some((row) => row.key === r.user) ? "Shown as " + r.user + "." : "No requests from this person in this range (" + r.user + ").";
  });
  return card("By user", h("p", { class: "muted" }, "Requests that named a person with a user token (X-KyGate-User). People are shown by pseudonym: KyGate keeps no IDs."), f, st, box);
}

function userKeyActions(k) {
  const once = h("span");
  const secret = h("button", { class: "small ghost", type: "button" }, k.user_tokens ? "New signing secret" : "Signing secret");
  secret.addEventListener("click", async () => {
    if (k.user_tokens && !confirm("Replace the signing secret of " + k.name + "? Tokens signed with the old one stop working at once.")) return;
    try {
      const r = await apiWrite("POST", "admin/keys/" + encodeURIComponent(k.name) + "/user-secret");
      once.replaceChildren(h("div", { class: "banner warn" }, h("strong", {}, "Copy this signing secret now: it is shown once"), h("div", { class: "secret-once" }, r.secret)));
    } catch (err) { if (err.message !== "unauthorized") alert(err.message); }
  });
  const req = h("button", { class: "small ghost", type: "button" }, k.require_user ? "Stop requiring a user" : "Require a user");
  req.addEventListener("click", async () => {
    if (!k.require_user && !confirm("Refuse requests on " + k.name + " that carry no valid user token?")) return;
    try { await apiWrite("PUT", "admin/keys/" + encodeURIComponent(k.name) + "/require-user", { required: !k.require_user }); setTimeout(route, 600); }
    catch (err) { if (err.message !== "unauthorized") alert(err.message); }
  });
  return h("span", {}, secret, " ", req, once);
}

// ---------- audit integrity and SIEM export (GV-3) ----------
function reportView(r) {
  const rows = [
    ["Result", r.ok ? h("span", { class: "pill good" }, "intact") : h("span", { class: "pill critical" }, "problems found")],
    ["Chain", r.chain_ok ? "every entry links to the one before" : "broken: " + r.broken],
    ["Sealed", count(r.events) + " events, " + count(r.admin) + " administration records"],
    ["Removed by recorded retention or purges", count(r.removed)],
  ];
  if (r.unsigned) rows.push(["Recorded before events were signed", count(r.unsigned)]);
  if (r.altered_count) rows.push(["Altered", count(r.altered_count) + ": " + r.altered.join(", ")]);
  if (r.missing_count) rows.push(["Missing, with no recorded deletion", count(r.missing_count) + ": " + r.missing.join(", ")]);
  if (r.forged_count) rows.push(["Forged gateway signature", count(r.forged_count) + ": " + r.forged.join(", ")]);
  if (r.unrecorded) rows.push(["Marked sealed, not in the ledger", count(r.unrecorded)]);
  rows.push(["Checked", when(r.checked) + " in " + r.took_ms + " ms"]);
  return table([{ label: "", get: (x) => x[0] }, { label: "", get: (x) => x[1] }], rows);
}

// isEnterprise: the Enterprise capabilities are built into this KyGate.
function isEnterprise() {
  return !!(state.info && state.info.edition === "enterprise");
}

// enterpriseCard stands in for a capability of the Enterprise edition.
function enterpriseCard(title, text) {
  return card(title,
    h("p", { class: "muted" }, text),
    h("p", { class: "muted" }, "To learn about KyGate Enterprise, see 'For companies' in KyGate's README."));
}

async function integrityCard() {
  if (!isEnterprise()) {
    return enterpriseCard("Audit integrity",
      "Every request is recorded in the audit trail, and each gateway signs its events. The tamper-evident ledger, its verification, and SIEM export are part of KyGate Enterprise.");
  }
  const a = await api("admin/audit");
  const result = h("div", {}, a.last_verification ? reportView(a.last_verification) : h("p", { class: "muted" }, "Not verified since the control process started."));
  const st = statusLine();
  const verify = h("button", { type: "button" }, "Verify now");
  verify.addEventListener("click", async () => {
    verify.disabled = true;
    say(st, true, "Verifying the whole ledger…");
    try { const r = await apiWrite("POST", "admin/audit/verify"); result.replaceChildren(reportView(r)); say(st, r.ok, r.ok ? "Intact." : "Problems found: see below. The check is in the audit trail."); }
    catch (err) { if (err.message !== "unauthorized") say(st, false, err.message); }
    verify.disabled = false;
  });
  const dests = a.destinations || [];
  return card("Audit integrity",
    h("p", { class: "muted" }, "Every request event and administration record is sealed into an append-only ledger of keyed digests, each entry chained to the one before. Gateways sign their events. Retention and purges are recorded, so a verification tells them apart from changes made behind KyGate's back."),
    h("div", { class: "tiles" },
      tile("Ledger entries", count(a.head_seq), a.head_hash ? "head " + a.head_hash.slice(0, 16) + "…" : "empty"),
      tile("Waiting to be sealed", count(a.pending_events + a.pending_admin), "sealed within seconds")),
    h("div", { class: "admin-form" }, verify), st, result,
    h("h3", {}, "SIEM export"),
    dests.length ? table([
      { label: "Destination", get: (d) => h("span", { class: "mono" }, d.name) },
      { label: "Type", get: (d) => d.type },
      { label: "Behind", num: true, get: (d) => count(d.lag) },
      { label: "Sent", num: true, get: (d) => count(d.sent) },
      { label: "Last success", get: (d) => d.last_ok && !d.last_ok.startsWith("0001") ? when(d.last_ok) : "–" },
      { label: "State", get: (d) => d.last_error ? h("span", { class: "pill critical" }, d.last_error) : h("span", { class: "pill good" }, "ok") },
    ], dests) : h("p", { class: "muted" }, "No destination. List them in siem.yaml in the control process's data directory: webhook (JSON lines, Splunk HEC, Elastic bulk), syslog (RFC 5424 over TLS, TCP, or UDP), or OpenTelemetry logs."));
}
