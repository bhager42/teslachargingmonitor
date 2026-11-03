// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// Progressive enhancement for Tesla Charger Monitoring. Every page works
// without this script. It never builds HTML from strings (only DOM nodes),
// so it runs under the strict CSP with Trusted Types enforced.

const SVG = 'http://www.w3.org/2000/svg';

// ---- Theme: Auto / Dark / Light, remembered in a cookie so the server
// renders the right theme on the first paint (no flash). ----
function initTheme() {
  const root = document.documentElement;
  for (const btn of document.querySelectorAll('[data-set-theme]')) {
    btn.addEventListener('click', () => {
      const theme = btn.dataset.setTheme;
      root.dataset.theme = theme;
      const secure = location.protocol === 'https:' ? '; Secure' : '';
      document.cookie = `tcmon_theme=${theme}; Path=/; Max-Age=31536000; SameSite=Strict${secure}`;
      try { localStorage.setItem('tcmon_theme', theme); } catch { /* storage unavailable */ }
      for (const b of document.querySelectorAll('[data-set-theme]')) {
        b.setAttribute('aria-pressed', String(b === btn));
      }
    });
  }
}

// ---- Relative times ("5 min ago") kept fresh. ----
function ago(iso) {
  if (!iso) return 'never';
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 172800) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} days ago`;
}

function refreshTimes() {
  for (const el of document.querySelectorAll('[data-ts]')) {
    if (el.dataset.ts) el.textContent = ago(el.dataset.ts);
  }
}

// ---- Live updates over Server-Sent Events. ----
function applyCard(card) {
  for (const root of document.querySelectorAll(`[data-device-id="${card.id}"]`)) {
    root.className = root.className.replace(/\bstate-\S+/, `state-${card.state_class}`);
    const st = root.querySelector('[data-role="state-text"]');
    if (st) st.textContent = card.state;
    for (const [key, value] of Object.entries(card.fields)) {
      const el = root.querySelector(`[data-field="${key}"]`);
      if (el && el.textContent !== value) el.textContent = value;
    }
    const upd = root.querySelector('[data-role="updated"]');
    if (upd) { upd.dataset.ts = card.updated_at; upd.textContent = ago(card.updated_at); }
    root.querySelector('[data-role="stale"]')?.remove();
    const meter = root.querySelector('[data-role="meter"]');
    if (meter) { meter.value = card.current_pct; meter.textContent = `${card.current_pct}%`; }
    const list = root.querySelector('[data-role="alerts"]');
    if (list) {
      list.replaceChildren(...(card.alerts || []).map((a) => {
        const li = document.createElement('li');
        li.className = `sev-${a.severity}`;
        const badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = a.severity;
        li.append(badge, ` ${a.title}`);
        return li;
      }));
    }
  }
}

function announceAlerts(items) {
  const region = document.getElementById('live-alerts');
  if (!region) return;
  for (const a of items) {
    const p = document.createElement('p');
    p.className = `sev-${a.Severity}`;
    const link = document.createElement('a');
    link.href = '/alerts';
    link.textContent = 'View alerts';
    p.append(`${a.Kind === 'resolved' ? 'Resolved' : 'New alert'}: ${a.Title} — ${a.Device}. `, link);
    region.prepend(p);
  }
  while (region.childElementCount > 3) region.lastElementChild.remove();
}

function initLive() {
  if (!document.querySelector('[data-live]') || !('EventSource' in window)) return;
  const es = new EventSource('/events');
  es.addEventListener('device', (e) => applyCard(JSON.parse(e.data)));
  es.addEventListener('alerts', (e) => announceAlerts(JSON.parse(e.data)));
}

// ---- <tcmon-chart>: small, dependency-free SVG line chart. ----
const fmt = (v) => (Math.abs(v) >= 100 ? v.toFixed(0) : v.toFixed(1));

class TcmonChart extends HTMLElement {
  async connectedCallback() {
    const { device, metric, range, label } = this.dataset;
    const url = `/api/devices/${encodeURIComponent(device)}/series?metric=${encodeURIComponent(metric)}&range=${encodeURIComponent(range)}`;
    try {
      const res = await fetch(url, { credentials: 'same-origin', signal: AbortSignal.timeout(15000) });
      if (!res.ok) throw new Error(String(res.status));
      this.draw(await res.json(), label, range);
    } catch {
      this.message('Could not load the chart.');
    }
  }

  message(text) {
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = text;
    this.replaceChildren(p);
  }

  draw(data, label, range) {
    const pts = data.points;
    if (!pts.length) { this.message(`No data in the last ${range}.`); return; }
    const W = 600, H = 160, L = 44, B = 18;
    const t0 = Date.parse(pts[0].t), t1 = Date.parse(pts.at(-1).t) || t0 + 1;
    let lo = Math.min(...pts.map((p) => p.min)), hi = Math.max(...pts.map((p) => p.max));
    if (hi - lo < 1e-9) { lo -= 1; hi += 1; }
    const x = (t) => L + ((Date.parse(t) - t0) / Math.max(t1 - t0, 1)) * (W - L - 4);
    const y = (v) => 4 + (1 - (v - lo) / (hi - lo)) * (H - B - 8);
    const el = (name, attrs) => {
      const n = document.createElementNS(SVG, name);
      for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
      return n;
    };
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', preserveAspectRatio: 'none' });
    const latest = pts.at(-1).avg;
    const summary = `${label}, last ${range}: minimum ${fmt(lo)}, maximum ${fmt(hi)}, latest ${fmt(latest)} ${data.unit}`;
    svg.setAttribute('aria-label', summary);
    const band = pts.map((p) => `${x(p.t)},${y(p.max)}`).concat(pts.toReversed().map((p) => `${x(p.t)},${y(p.min)}`));
    svg.append(
      el('line', { class: 'chart-axis', x1: L, y1: H - B, x2: W, y2: H - B }),
      el('line', { class: 'chart-axis', x1: L, y1: 0, x2: L, y2: H - B }),
      el('polygon', { class: 'chart-band', points: band.join(' ') }),
      el('polyline', { class: 'chart-line', points: pts.map((p) => `${x(p.t)},${y(p.avg)}`).join(' ') }),
      // Always mark the latest reading (a single reading has no line).
      el('circle', { class: 'chart-dot', cx: x(pts.at(-1).t), cy: y(latest), r: 3.5 }),
    );
    const text = (s, attrs) => { const t = el('text', { class: 'chart-text', ...attrs }); t.textContent = s; return t; };
    const when = (ms) => new Intl.DateTimeFormat(undefined, range === '24h'
      ? { hour: '2-digit', minute: '2-digit' } : { month: 'short', day: 'numeric' }).format(ms);
    svg.append(
      text(fmt(hi), { x: L - 6, y: 12, 'text-anchor': 'end' }),
      text(fmt(lo), { x: L - 6, y: H - B, 'text-anchor': 'end' }),
      text(when(t0), { x: L, y: H - 4 }),
      text(when(t1), { x: W, y: H - 4, 'text-anchor': 'end' }),
    );
    const caption = document.createElement('p');
    caption.className = 'sr-only';
    caption.textContent = summary;
    this.replaceChildren(svg, caption);
  }
}

if (!customElements.get('tcmon-chart')) customElements.define('tcmon-chart', TcmonChart);
initTheme();
initLive();
refreshTimes();
setInterval(refreshTimes, 30000);
