// Threat Intel HUD. Three views: overview tables, pivot search + enrichment, feeds + brief.
// Wrapped in a function so these names do not clash with the globals hud.js defines.
(() => {
const { api, toast, esc, renderTable, severityTag, forceGraph, fmtTime } = window.hud;

const num = (v, d = 1) => (v === null || v === undefined ? "-" : Number(v).toFixed(d));
const when = (t) => (t ? fmtTime(t) : "-");
const pivotLink = (v) => `<a href="#search" data-pivot="${esc(v)}">${esc(v)}</a>`;
const list = (xs) => esc((xs || []).join(", "));

document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-pivot]");
  if (a) { e.preventDefault(); show("search"); runSearch(a.dataset.pivot); }
});

// ------------------------------------------------------------ overview

async function loadOverview() {
  const ov = await api("/api/overview");
  const c = ov.counts;
  const stat = (v, l) => `<div class="stat">${esc(v)}<small>${esc(l)}</small></div>`;
  document.getElementById("stats").innerHTML = [
    stat(c.indicators, "indicators"), stat(c.c2_ips, "C2 IPs"), stat(c.phishing_urls, "phishing URLs"),
    stat(c.drop_netblocks, "DROP blocks"), stat(c.vulnerabilities, "KEV CVEs"), stat(c.kev_ransomware, "KEV w/ ransomware"),
    stat(c.actors, "actors"), stat(c.merged_actors, "merged actors"), stat(c.victims, "victim posts"),
  ].join("");
  const lc = ov.last_correlate;
  document.getElementById("ov-note").textContent = c.indicators + c.vulnerabilities === 0
    ? "Database is empty. Go to Feeds & Brief and press 'Load demo data' (no network needed)."
    : `Last correlation: ${lc ? fmtTime(lc.at) : "never"}. Indicator confidence: ${ov.formulas.indicator}`;
  document.getElementById("rw-anchor").textContent = `7/30-day windows end ${ov.anchor.victims}. Claims by criminals, not verified.`;
  await Promise.all([loadVulns(), loadRansomware(), loadAttack(), loadInfra(), loadPhishing(), loadTrends()]);
}

async function loadPhishing() {
  const data = await api("/api/phishing?limit=40&min_score=30");
  document.getElementById("phish-formula").textContent = data.formula;
  renderTable("#phish-top", data.rows, [
    { key: "score", label: "score", render: (v) => `<b>${esc(v)}</b>` },
    { key: "brand", label: "brand" }, { key: "method", label: "method" },
    { key: "value", label: "url / domain (defanged)", render: (v) => pivotLink(v) },
    { key: "sources", label: "sources", render: list },
    { key: "reasons", label: "reasons", render: (r) => esc((r || []).join("; ")) },
  ], { empty: "No phishing data yet." });
}

async function loadTrends() {
  const t = await api("/api/trends?days=30");
  document.getElementById("trend-note").textContent =
    `${t.history_days} day(s) of snapshots. Baseline (first collection) ${t.baseline_day || "-"}: it counts everything already listed as new. ${t.note}.`;
  renderTable("#trend-daily", t.daily, [
    { key: "day", label: "day", render: (v, r) => esc(v) + (r.baseline ? " (baseline)" : "") },
    { key: "indicators", label: "indicators" }, { key: "new_indicators", label: "new" },
    { key: "c2_ips", label: "C2 IPs" }, { key: "c2_certs", label: "C2 certs" }, { key: "new_c2", label: "new C2" },
    { key: "phishing_urls", label: "phish URLs" }, { key: "phishing_domains", label: "phish domains" },
    { key: "phishing_branded", label: "branded" }, { key: "victims", label: "victim posts" },
  ], { empty: "No history yet: run correlation once a day (the scheduler does it after each collection)." });
  renderTable("#trend-c2", t.c2_reported_by_family.slice(0, 40), [
    { key: "day", label: "day (feed date)" }, { key: "family", label: "family", render: (v) => pivotLink(v) }, { key: "n", label: "n" },
  ], { empty: "No dated C2 listings in 30 days." });
  renderTable("#trend-phish", t.phishing_by_brand.slice(0, 40), [
    { key: "day", label: "day (first observed)" }, { key: "key", label: "brand" }, { key: "n", label: "n" },
  ]);
  renderTable("#trend-rw", t.victims_by_week.slice(0, 40), [
    { key: "week", label: "week" }, { key: "group", label: "group", render: (v) => pivotLink(v) }, { key: "n", label: "posts" },
  ]);
}

async function loadVulns() {
  const rw = document.getElementById("rw-only").checked;
  const q = document.getElementById("vuln-q").value.trim();
  const data = await api(`/api/vulns?limit=60&ransomware=${rw}&q=${encodeURIComponent(q)}`);
  document.getElementById("vuln-formula").textContent = data.formula;
  renderTable("#vulns", data.rows, [
    { key: "cve", label: "CVE", render: (v) => pivotLink(v) },
    { key: "vendor", label: "vendor" }, { key: "product", label: "product" },
    { key: "priority", label: "priority", render: (v) => `<b>${num(v)}</b>` },
    { key: "priority_parts", label: "KEV + EPSS + CVSS + RW + recency", render: (p) =>
      esc(`${num(p.kev, 0)} + ${num(p.epss)} + ${num(p.cvss)}${p.cvss_assumed ? "*" : ""} + ${num(p.ransomware, 0)} + ${num(p.recency)}`) },
    { key: "epss", label: "EPSS", render: (v) => num(v, 3) },
    { key: "cvss", label: "CVSS", render: (v) => num(v) },
    { key: "ransomware_use", label: "ransomware", render: (v) => v === "Known" ? '<span class="tag crit">known</span>' : "" },
    { key: "date_added", label: "added" },
  ]);
}

async function loadRansomware() {
  const data = await api("/api/ransomware");
  renderTable("#rw-groups", data.groups, [
    { key: "name", label: "group", render: (v) => pivotLink(v) },
    { key: "attack_id", label: "ATT&CK" }, { key: "d7", label: "7d" }, { key: "d30", label: "30d" },
    { key: "top_sectors", label: "sectors", render: list }, { key: "top_countries", label: "countries", render: list },
  ]);
}

async function loadAttack() {
  const data = await api("/api/attack?scope=active&limit=40");
  renderTable("#techniques", data.techniques, [
    { key: "id", label: "technique", render: (v) => pivotLink(v) }, { key: "name", label: "name" },
    { key: "tactics", label: "tactics", render: list }, { key: "actors", label: `actors (of ${data.actors})` },
  ], { empty: "No active groups with TTP mappings yet." });
}

async function loadInfra() {
  const data = await api("/api/infrastructure");
  renderTable("#c2", data.c2_by_family, [
    { key: "family", label: "family", render: (v) => pivotLink(v) }, { key: "c2_ips", label: "C2 IPs" },
    { key: "countries", label: "countries" }, { key: "last_seen", label: "last seen", render: when },
  ]);
  renderTable("#clusters", data.clusters, [
    { key: "kind", label: "kind" }, { key: "key", label: "key" }, { key: "size", label: "size" },
    { key: "families", label: "families", render: list },
    { key: "members", label: "members (first)", render: (m) => m.slice(0, 4).map(pivotLink).join(" ") },
  ]);
  renderTable("#sources", data.by_source, [
    { key: "source", label: "source" }, { key: "indicators", label: "indicators" },
    { key: "new_observed", label: "new 7d" }, { key: "avg_confidence", label: "avg conf" },
    { key: "malicious_verdicts", label: "conf>=60" },
  ]);
  renderTable("#events", data.misp_events, [
    { key: "date", label: "date" }, { key: "org", label: "org" },
    { key: "info", label: "MISP event", render: (v, r) => `<a href="#search" data-pivot="event:${esc(r.uuid)}">${esc(v)}</a>` },
    { key: "stored", label: "IOCs" }, { key: "malware", label: "malware", render: list },
  ], { empty: "No MISP events collected." });
  const p = data.phishing;
  const a = p.analysis || { by_source: {} };
  const small = (rows) => rows.slice(0, 8).map((r) => `${esc(r.label)} (${r.value})`).join(", ") || "-";
  const before = Object.entries(a.by_source).map(([k, v]) =>
    `${esc(k)}: ${v.total} total, unbranded ${v.unbranded} (${v.unbranded_pct}%), keyword-only matcher ${v.unbranded_keyword_only} (${v.unbranded_pct_keyword_only}%)`).join("<br>");
  document.getElementById("phish").innerHTML =
    `<p>${p.total} URLs, ${p.unbranded} without a brand match.</p><p class="muted">${before || ""}</p>
     <p class="muted">methods: ${small(a.methods || [])}</p>
     <table><tbody>
       <tr><th>brands</th><td>${small(p.brands)}</td></tr>
       <tr><th>TLDs</th><td>${small(p.tlds)}</td></tr>
       <tr><th>hosting</th><td>${small(p.hosting)}</td></tr>
       <tr><th>registered domains</th><td>${small(p.registered_domains)}</td></tr>
       <tr><th>IPs inside DROP</th><td>${data.drop_overlaps.length ? data.drop_overlaps.slice(0, 10).map((d) => pivotLink(d.ip)).join(" ") : "-"}</td></tr>
     </tbody></table>`;
}

// ------------------------------------------------------------ search

const GRAPH_COLORS = { actor: "#b8322a", technique: "#7a5cff", software: "#d49a1e", malware: "#c0607a", cve: "#e04a3a",
  ip: "#4f8fb8", url: "#3fa7a0", domain: "#5f9e5a", hash: "#8b877d" };

async function runSearch(q) {
  q = (q || document.getElementById("q").value).trim();
  if (!q) return;
  document.getElementById("q").value = q;
  const withRdap = document.getElementById("q-rdap").checked;
  const res = await api(`/api/search?q=${encodeURIComponent(q)}&rdap=${withRdap}`);
  const ent = document.getElementById("entity");
  if (!res.found) {
    ent.innerHTML = `<p class="muted">No match for ${esc(q)} (${esc(res.kind)}).</p>` +
      (res.suggestions.length ? "<p>Did you mean: " + res.suggestions.map((s) => pivotLink(s.value.split(" ")[0])).join(" ") + "</p>" : "");
    document.getElementById("graph").innerHTML = "";
    document.getElementById("linked").innerHTML = "";
    return;
  }
  const e = res.entity || {};
  const rows = Object.entries(e).filter(([k, v]) => v !== null && v !== "" && !["sightings", "stix_id", "id"].includes(k));
  if (res.rdap) rows.push(["rdap", res.rdap]);
  ent.innerHTML = `<table><tbody>${rows.map(([k, v]) =>
    `<tr><th>${esc(k)}</th><td>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</td></tr>`).join("")}</tbody></table>`;
  // The shared force layout gets crowded past ~25 nodes; keep the start node and the most
  // useful neighbours (techniques last). The tables below still list everything.
  const rank = { actor: 0, malware: 1, software: 2, cve: 3, ip: 4, domain: 4, url: 5, hash: 5, technique: 9 };
  const nodes = [...res.graph.nodes].sort((a, b) => (b.start - a.start) || ((rank[a.type] ?? 6) - (rank[b.type] ?? 6))).slice(0, 25);
  const keep = new Set(nodes.map((n) => n.id));
  const links = res.graph.links.filter((l) => keep.has(l.source) && keep.has(l.target));
  forceGraph("#graph", nodes, links, {
    width: 1100, height: 520, colors: GRAPH_COLORS,
    onClick: (n) => runSearch(n.id),
  });
  const linked = document.getElementById("linked");
  linked.innerHTML = "";
  for (const [section, items] of Object.entries(res.linked)) {
    if (!items.length) continue;
    const div = document.createElement("div");
    div.innerHTML = `<h2 style="margin-top:14px">${esc(section)} (${items.length})</h2><div class="scroll"></div>`;
    linked.appendChild(div);
    const keys = Object.keys(items[0]);
    renderTable(div.querySelector(".scroll"), items, keys.map((k) => ({
      key: k, label: k,
      render: (v) => {
        if (Array.isArray(v)) return list(v);
        if (["cve", "value", "name", "victim"].includes(k) && section !== "recent_victims" && v) return pivotLink(v);
        return esc(v);
      },
    })));
  }
}

const EXAMPLES = ["akira", "qakbot", "T1486", "Cobalt Strike"];

async function loadExamples() {
  const ex = [...EXAMPLES];
  try {
    const v = await api("/api/vulns?limit=1&ransomware=true");
    if (v.rows[0]) ex.unshift(v.rows[0].cve);
    const ips = await api("/api/indicators?type=ip&limit=1");
    if (ips[0]) ex.push(ips[0].value);
  } catch (err) { /* empty db is fine */ }
  document.getElementById("examples").innerHTML = ex.map(pivotLink).join(" ");
}

async function runEnrich() {
  const text = document.getElementById("ioc-text").value.trim();
  if (!text) return toast("Paste some IOCs first");
  let body;
  try { const j = JSON.parse(text); body = j.type === "bundle" ? j : { iocs: [].concat(j) }; }
  catch { body = { text }; }
  const withRdap = document.getElementById("enrich-rdap").checked;
  const res = await api(`/api/enrich?rdap=${withRdap}`, { method: "POST", body });
  document.getElementById("enrich-summary").textContent = JSON.stringify(res.summary);
  renderTable("#enrich-out", res.results, [
    { key: "input", label: "input" }, { key: "type", label: "type" },
    { key: "verdict", label: "verdict", render: (v) => severityTag(v === "malicious" ? "crit" : v === "suspicious" ? "warn" : v) },
    { key: "confidence", label: "conf" }, { key: "sources", label: "sources", render: list },
    { key: "malware", label: "malware" },
    { key: "actors", label: "actors", render: (a) => (a || []).map((x) => pivotLink(x.name)).join(" ") },
    { key: "inside_drop", label: "DROP" },
    { key: "asn", label: "ASN", render: (a) => (a ? esc(`AS${a.asn} ${a.as_name || ""} ${a.country || ""}`) : "") },
    { key: "rdap", label: "registered / registrar / abuse", render: (r) => (r ? esc(`${(r.registered || r.status || "").slice(0, 10)} ${r.registrar || r.network || ""} ${r.abuse_email || ""}`) : "") },
    { key: "phishing", label: "phish score", render: (p) => (p ? esc(`${p.score} ${(p.brands || []).join(",")}`) : "") },
    { key: "tags", label: "tags", render: list },
  ]);
}

async function sampleEnrich() {
  const ips = await api("/api/indicators?type=ip&limit=3");
  const urls = await api("/api/indicators?type=url&limit=2");
  const hashes = await api("/api/indicators?type=hash&limit=1");
  document.getElementById("ioc-text").value = [...ips, ...urls, ...hashes].map((i) => i.value)
    .concat(["8.8.8.8", "example.org"]).join("\n");
}

// ------------------------------------------------------------ feeds and brief

async function loadFeeds() {
  const data = await api("/api/feeds");
  const s = data.scheduler;
  const sb = document.getElementById("sched");
  sb.textContent = `Scheduler: ${s.enabled ? "ON" : "off"}`;
  sb.classList.toggle("primary", s.enabled);
  renderTable("#feed-table", data.feeds, [
    { key: "feed", label: "feed", render: (v, r) => `<a href="${esc(r.homepage)}" target="_blank" rel="noopener">${esc(v)}</a>` },
    { key: "enabled", label: "enabled", render: (v, r) => `<input type="checkbox" data-enable="${esc(r.feed)}" ${v ? "checked" : ""}>` },
    { key: "last_run", label: "last status", render: (v) => v ? severityTag(v.status === "ok" || v.status === "seeded" || v.status === "cached" ? "ok" : v.status === "error" ? "crit" : "warn") + " " + esc(v.status) : "never" },
    { key: "last_run", label: "rows", render: (v) => esc(v ? v.rows : "") },
    { key: "last_run", label: "when / mode", render: (v) => v ? esc(`${when(v.ended || v.started)} ${v.mode}`) : "" },
    { key: "key_env", label: "API key", render: (v, r) => v ? esc(`${v} ${r.key_present ? "set" : r.key_required ? "MISSING" : "optional"}`) : "" },
    { key: "interval_min", label: "every (min)" },
    { key: "last_run", label: "error", render: (v) => `<span class="muted">${esc(v && v.error ? v.error.slice(0, 140) : "")}</span>` },
    { key: "feed", label: "", render: (v) => `<button class="btn" data-refresh="${esc(v)}">refresh</button>` },
  ]);
  const runs = await api("/api/feeds/runs?limit=25");
  renderTable("#runs", runs, [
    { key: "feed", label: "feed" }, { key: "status", label: "status" }, { key: "rows", label: "rows" },
    { key: "mode", label: "mode" }, { key: "started", label: "started", render: when },
    { key: "ended", label: "secs", render: (v, r) => (v ? (v - r.started).toFixed(1) : "...") },
  ]);
  const reps = await api("/api/reports");
  renderTable("#reports", reps, [
    { key: "name", label: "brief" }, { key: "modified", label: "created", render: when },
    { key: "name", label: "", render: (v) => `<a href="/api/reports/${esc(v)}.html" target="_blank">view</a> &middot;
      <a href="/api/reports/${esc(v)}.md?download=true">md</a> &middot; <a href="/api/reports/${esc(v)}.html?download=true">html</a>` },
  ], { empty: "No briefs yet." });
}

async function watchJob(job, label) {
  const el = document.getElementById("job");
  el.textContent = `${label}: running...`;
  for (;;) {
    await new Promise((r) => setTimeout(r, 1500));
    const j = await api(`/api/jobs/${job.id}`);
    if (j.status !== "running") {
      const st = j.result && j.result.status ? j.result.status : j.status;
      el.textContent = `${label}: ${st}${j.error ? " " + j.error : ""}`;
      toast(`${label}: ${st}`);
      await loadFeeds();
      return j;
    }
    if (document.querySelector("#feeds.active")) loadFeeds();
  }
}

document.getElementById("feed-table").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-refresh]");
  if (b) watchJob(await api(`/api/feeds/${b.dataset.refresh}/refresh`, { method: "POST" }), `refresh ${b.dataset.refresh}`);
});
document.getElementById("feed-table").addEventListener("change", async (e) => {
  const c = e.target.closest("[data-enable]");
  if (c) { await api(`/api/feeds/${c.dataset.enable}/enable`, { method: "POST", body: { enabled: c.checked } }); toast(`${c.dataset.enable}: ${c.checked ? "enabled" : "disabled"}`); }
});
document.getElementById("seed").onclick = async () => { await watchJob(await api("/api/seed", { method: "POST" }), "seed"); loadExamples(); };
document.getElementById("correlate").onclick = async () => watchJob(await api("/api/correlate", { method: "POST" }), "correlate");
document.getElementById("sched").onclick = async () => {
  const cur = (await api("/api/feeds")).scheduler.enabled;
  await api("/api/scheduler", { method: "POST", body: { enabled: !cur } });
  loadFeeds();
};
document.getElementById("brief").onclick = async () => {
  const days = document.getElementById("brief-days").value || 7;
  const r = await api(`/api/reports?days=${days}`, { method: "POST" });
  toast(`Brief written: ${r.name}`);
  loadFeeds();
  window.open(`/api/reports/${r.name}.html`, "_blank");
};
document.getElementById("go").onclick = () => runSearch();
document.getElementById("q").addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });
document.getElementById("enrich").onclick = runEnrich;
document.getElementById("enrich-sample").onclick = sampleEnrich;
document.getElementById("rw-only").onchange = loadVulns;
document.getElementById("vuln-q").addEventListener("input", () => { clearTimeout(window._vq); window._vq = setTimeout(loadVulns, 300); });

const show = window.hud.initTabs((id) => {
  const run = { overview: loadOverview, search: loadExamples, feeds: loadFeeds }[id];
  if (run) run().catch((err) => toast(err.message));
});
api("/api/health").then((h) => { document.getElementById("sub").textContent = `${h.name} ${h.version} :8102`; });
})();
