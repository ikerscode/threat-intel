// seclab HUD helpers - dependency-free SVG charts, tables, tabs and fetch wrappers.
// Shared across all lab dashboards so they behave the same way.

const NS = "http://www.w3.org/2000/svg";
const PALETTE = ["#b8322a", "#7a5cff", "#4f8fb8", "#d49a1e", "#5f9e5a", "#c0607a", "#8b877d", "#3fa7a0"];

function svgEl(tag, attrs = {}, parent) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (parent) parent.appendChild(el);
  return el;
}

function resolve(target) {
  return typeof target === "string" ? document.querySelector(target) : target;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(path, options = {}) {
  const opts = { ...options };
  if (opts.body && typeof opts.body !== "string" && !(opts.body instanceof FormData)) {
    opts.body = JSON.stringify(opts.body);
    opts.headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text.slice(0, 300)}`);
  }
  const type = res.headers.get("content-type") || "";
  return type.includes("application/json") ? res.json() : res.text();
}

function toast(message, ms = 3500) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = message;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

// Tabs: buttons with data-view="id" inside header nav, sections with class "view" and matching id.
function initTabs(onChange) {
  const buttons = document.querySelectorAll("header.hud nav button[data-view]");
  const show = (id) => {
    buttons.forEach((b) => b.classList.toggle("active", b.dataset.view === id));
    document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === id));
    location.hash = id;
    if (onChange) onChange(id);
  };
  buttons.forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
  const first = location.hash.slice(1) || (buttons[0] && buttons[0].dataset.view);
  if (first) show(first);
  return show;
}

// Render an array of objects as a table. columns: [{key, label, render?}]
function renderTable(target, rows, columns, { empty = "No data yet." } = {}) {
  const el = resolve(target);
  if (!rows || rows.length === 0) { el.innerHTML = `<p class="muted">${esc(empty)}</p>`; return; }
  const cols = columns || Object.keys(rows[0]).map((k) => ({ key: k, label: k }));
  const head = cols.map((c) => `<th>${esc(c.label ?? c.key)}</th>`).join("");
  const body = rows.map((r) => "<tr>" + cols.map((c) => `<td>${c.render ? c.render(r[c.key], r) : esc(r[c.key])}</td>`).join("") + "</tr>").join("");
  el.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function severityTag(sev) {
  const s = String(sev || "").toLowerCase();
  const cls = ["critical", "high", "crit", "malicious"].includes(s) ? "crit"
    : ["medium", "warn", "suspicious"].includes(s) ? "warn"
    : ["low", "ok", "benign", "clean"].includes(s) ? "ok" : "info";
  return `<span class="tag ${cls}">${esc(sev)}</span>`;
}

// Horizontal bar chart. data: [{label, value}]
function barChart(target, data, { width = 520, barHeight = 18, color = PALETTE[0], max } = {}) {
  const el = resolve(target);
  el.innerHTML = "";
  if (!data.length) { el.innerHTML = '<p class="muted">No data yet.</p>'; return; }
  const labelW = Math.min(200, Math.max(...data.map((d) => String(d.label).length)) * 7 + 10);
  const h = data.length * (barHeight + 6) + 4;
  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${h}`, class: "chart" }, el);
  const top = max ?? Math.max(...data.map((d) => d.value), 1);
  data.forEach((d, i) => {
    const y = i * (barHeight + 6) + 2;
    const w = ((width - labelW - 60) * d.value) / top;
    const label = String(d.label);
    svgEl("text", { x: 0, y: y + barHeight - 5 }, svg).textContent = label.length > 28 ? label.slice(0, 27) + "…" : label;
    svgEl("rect", { x: labelW, y, width: Math.max(w, 1), height: barHeight, fill: d.color || color, rx: 2 }, svg);
    svgEl("text", { x: labelW + w + 6, y: y + barHeight - 5 }, svg).textContent = d.value;
  });
}

// Line chart. series: [{name, points: [[x, y], ...]}], x numeric (e.g. epoch seconds) or index.
function lineChart(target, series, { width = 640, height = 220, xFormat = (x) => x, yLabel = "", thresholds = [] } = {}) {
  const el = resolve(target);
  el.innerHTML = "";
  const all = series.flatMap((s) => s.points);
  if (!all.length) { el.innerHTML = '<p class="muted">No data yet.</p>'; return; }
  const pad = { l: 44, r: 10, t: 10, b: 26 };
  const xs = all.map((p) => p[0]); const ys = all.map((p) => p[1]).concat(thresholds.map((t) => t.value));
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  const y0 = Math.min(0, ...ys), y1 = Math.max(...ys, 1);
  const sx = (x) => pad.l + ((x - x0) / (x1 - x0 || 1)) * (width - pad.l - pad.r);
  const sy = (y) => height - pad.b - ((y - y0) / (y1 - y0 || 1)) * (height - pad.t - pad.b);
  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, class: "chart" }, el);
  for (let i = 0; i <= 4; i++) {
    const yv = y0 + ((y1 - y0) * i) / 4;
    svgEl("line", { x1: pad.l, x2: width - pad.r, y1: sy(yv), y2: sy(yv), stroke: "#24232a" }, svg);
    svgEl("text", { x: 2, y: sy(yv) + 4 }, svg).textContent = Number(yv.toFixed(1));
  }
  [x0, (x0 + x1) / 2, x1].forEach((xv, i) => {
    svgEl("text", { x: sx(xv) - (i === 2 ? 60 : i === 1 ? 30 : 0), y: height - 6 }, svg).textContent = xFormat(xv);
  });
  thresholds.forEach((t) => {
    svgEl("line", { x1: pad.l, x2: width - pad.r, y1: sy(t.value), y2: sy(t.value), stroke: t.color || "#e04a3a", "stroke-dasharray": "4 4" }, svg);
    svgEl("text", { x: width - pad.r - 90, y: sy(t.value) - 3 }, svg).textContent = t.label || "";
  });
  series.forEach((s, i) => {
    const d = s.points.map((p, j) => `${j ? "L" : "M"}${sx(p[0]).toFixed(1)},${sy(p[1]).toFixed(1)}`).join("");
    svgEl("path", { d, fill: "none", stroke: s.color || PALETTE[i % PALETTE.length], "stroke-width": 1.8 }, svg);
  });
  if (series.length > 1 || yLabel) {
    const legend = document.createElement("div");
    legend.className = "row muted";
    legend.style.fontSize = "11px";
    legend.innerHTML = (yLabel ? `<span>${esc(yLabel)}</span>` : "") + series.map((s, i) =>
      `<span><span style="color:${s.color || PALETTE[i % PALETTE.length]}">■</span> ${esc(s.name)}</span>`).join("");
    el.appendChild(legend);
  }
}

// Heatmap. matrix[row][col] numbers.
function heatmap(target, matrix, rowLabels, colLabels, { cell = 18, color = "184,50,42" } = {}) {
  const el = resolve(target);
  el.innerHTML = "";
  const max = Math.max(1, ...matrix.flat());
  const lw = 40, th = 16;
  const w = lw + colLabels.length * cell, h = th + rowLabels.length * cell;
  const svg = svgEl("svg", { viewBox: `0 0 ${w} ${h}`, class: "chart" }, el);
  colLabels.forEach((c, j) => { if (j % Math.ceil(colLabels.length / 12) === 0) svgEl("text", { x: lw + j * cell, y: 11 }, svg).textContent = c; });
  matrix.forEach((row, i) => {
    svgEl("text", { x: 0, y: th + i * cell + cell - 5 }, svg).textContent = rowLabels[i];
    row.forEach((v, j) => {
      const r = svgEl("rect", { x: lw + j * cell, y: th + i * cell, width: cell - 2, height: cell - 2, fill: `rgba(${color},${v ? 0.12 + 0.88 * (v / max) : 0.03})`, rx: 2 }, svg);
      svgEl("title", {}, r).textContent = `${rowLabels[i]} ${colLabels[j]}: ${v}`;
    });
  });
}

// Simple force-directed graph. nodes: [{id, label, type}], links: [{source, target}]
function forceGraph(target, nodes, links, { width = 900, height = 520, colors = {}, onClick } = {}) {
  const el = resolve(target);
  el.innerHTML = "";
  if (!nodes.length) { el.innerHTML = '<p class="muted">No data yet.</p>'; return; }
  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, class: "chart" }, el);
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const pts = nodes.map((n, i) => ({ ...n, x: width / 2 + Math.cos(i) * 150 * Math.random(), y: height / 2 + Math.sin(i) * 150 * Math.random(), vx: 0, vy: 0 }));
  const edges = links.filter((l) => idx.has(l.source) && idx.has(l.target)).map((l) => [idx.get(l.source), idx.get(l.target)]);
  for (let step = 0; step < 300; step++) {
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
      const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y, d2 = dx * dx + dy * dy + 0.01;
      const f = 900 / d2; pts[i].vx += dx * f; pts[i].vy += dy * f; pts[j].vx -= dx * f; pts[j].vy -= dy * f;
    }
    edges.forEach(([a, b]) => {
      const dx = pts[b].x - pts[a].x, dy = pts[b].y - pts[a].y;
      pts[a].vx += dx * 0.01; pts[a].vy += dy * 0.01; pts[b].vx -= dx * 0.01; pts[b].vy -= dy * 0.01;
    });
    pts.forEach((p) => {
      p.vx += (width / 2 - p.x) * 0.002; p.vy += (height / 2 - p.y) * 0.002;
      p.x = Math.max(20, Math.min(width - 20, p.x + p.vx * 0.5)); p.y = Math.max(20, Math.min(height - 20, p.y + p.vy * 0.5));
      p.vx *= 0.6; p.vy *= 0.6;
    });
  }
  edges.forEach(([a, b]) => svgEl("line", { x1: pts[a].x, y1: pts[a].y, x2: pts[b].x, y2: pts[b].y, stroke: "#2b2a31" }, svg));
  const types = [...new Set(nodes.map((n) => n.type))];
  pts.forEach((p) => {
    const g = svgEl("g", { style: "cursor:pointer" }, svg);
    svgEl("circle", { cx: p.x, cy: p.y, r: 6, fill: colors[p.type] || PALETTE[types.indexOf(p.type) % PALETTE.length] }, g);
    svgEl("text", { x: p.x + 8, y: p.y + 4 }, g).textContent = (p.label || p.id).slice(0, 24);
    svgEl("title", {}, g).textContent = `${p.type}: ${p.label || p.id}`;
    if (onClick) g.addEventListener("click", () => onClick(p));
  });
  const legend = document.createElement("div");
  legend.className = "row muted";
  legend.style.fontSize = "11px";
  legend.innerHTML = types.map((t) => `<span><span style="color:${colors[t] || PALETTE[types.indexOf(t) % PALETTE.length]}">●</span> ${esc(t)}</span>`).join("");
  el.appendChild(legend);
}

function every(ms, fn) { fn(); return setInterval(fn, ms); }
function fmtTime(epoch) { return new Date(epoch * 1000).toLocaleString(); }

window.hud = { api, toast, initTabs, renderTable, severityTag, barChart, lineChart, heatmap, forceGraph, every, fmtTime, esc, PALETTE };
