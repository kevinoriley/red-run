#!/usr/bin/env python3
"""Read-only web dashboard for engagement state.

Single-file HTTP server serving an inline HTML/CSS/JS dashboard with live
updates via SSE.  No dependencies beyond Python stdlib.

Authentication:
    If ~/.config/red-run/viewer-token exists, the server binds to 0.0.0.0
    and requires the token to access any endpoint.  Without a token file,
    it binds to 127.0.0.1 only (no auth needed).

    Generate a token:  bash operator/state-dashboard/generate-token.sh

Usage:
    python3 operator/state-dashboard/server.py [--port 8099] [--db engagement/state.db]
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import hmac
import json
import sqlite3
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from pathlib import Path
from urllib.parse import unquote_plus

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_DB = _PROJECT_ROOT / "engagement" / "state.db"
_TOKEN_FILE = Path.home() / ".config" / "red-run" / "viewer-token"

# Session cookie lifetime: 24 hours
_SESSION_MAX_AGE = 86400


def _load_token() -> str | None:
    """Load auth token from disk. Returns None if no token file."""
    if _TOKEN_FILE.exists():
        token = _TOKEN_FILE.read_text().strip()
        if token:
            return token
    return None


def _make_session_cookie(token: str) -> str:
    """Create an HMAC-signed session cookie value: timestamp.signature"""
    ts = str(int(time.time()))
    sig = hmac.new(token.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def _verify_session_cookie(cookie_val: str, token: str) -> bool:
    """Verify HMAC session cookie is valid and not expired."""
    parts = cookie_val.split(".", 1)
    if len(parts) != 2:
        return False
    ts_str, sig = parts
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if time.time() - ts > _SESSION_MAX_AGE:
        return False
    expected = hmac.new(token.encode(), ts_str.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def _get_local_ips() -> list[str]:
    """Return all non-loopback IPv4 addresses on this host."""
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if not ipaddress.ip_address(addr).is_loopback:
                ips.append(addr)
    except Exception:
        pass
    # Fallback: UDP connect trick for hosts where gethostname doesn't resolve
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            addr = s.getsockname()[0]
            s.close()
            if not ipaddress.ip_address(addr).is_loopback:
                ips.append(addr)
        except Exception:
            pass
    return sorted(set(ips))


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------


def _get_db(db_path: Path) -> sqlite3.Connection | None:
    """Open read-only connection. Returns None if DB doesn't exist."""
    if not db_path.exists():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _build_state(db_path: Path) -> dict:
    """Build full state JSON from all tables."""
    conn = _get_db(db_path)
    if conn is None:
        return {
            "engagement": None,
            "targets": [],
            "credentials": [],
            "access": [],
            "vulns": [],
            "pivot_map": [],
            "tunnels": [],
            "blocked": [],
            "events": [],
        }
    try:
        eng = _rows(conn, "SELECT * FROM engagement LIMIT 1")
        engagement = eng[0] if eng else None

        targets = _rows(conn, "SELECT * FROM targets ORDER BY id")
        for t in targets:
            t["ports"] = _rows(
                conn,
                "SELECT * FROM ports WHERE target_id = ? ORDER BY port",
                (t["id"],),
            )

        credentials = _rows(conn, "SELECT * FROM credentials ORDER BY id")
        for c in credentials:
            c["tested_against"] = _rows(
                conn,
                "SELECT ca.*, t.host FROM credential_access ca "
                "JOIN targets t ON t.id = ca.target_id "
                "WHERE ca.credential_id = ?",
                (c["id"],),
            )

        access = _rows(
            conn,
            "SELECT a.*, t.host FROM access a "
            "JOIN targets t ON t.id = a.target_id ORDER BY a.id",
        )
        vulns = _rows(
            conn,
            "SELECT v.*, t.host FROM vulns v "
            "LEFT JOIN targets t ON t.id = v.target_id ORDER BY v.id",
        )
        pivot_map = _rows(conn, "SELECT * FROM pivot_map ORDER BY id")
        tunnels = _rows(conn, "SELECT * FROM tunnels ORDER BY id")
        blocked = _rows(
            conn,
            "SELECT b.*, t.host FROM blocked b "
            "LEFT JOIN targets t ON t.id = b.target_id ORDER BY b.id",
        )
        events = _rows(
            conn,
            "SELECT * FROM state_events ORDER BY id DESC LIMIT 100",
        )

        return {
            "engagement": engagement,
            "targets": targets,
            "credentials": credentials,
            "access": access,
            "vulns": vulns,
            "pivot_map": pivot_map,
            "tunnels": tunnels,
            "blocked": blocked,
            "events": events,
        }
    finally:
        conn.close()


def _get_events_since(db_path: Path, since: int) -> list[dict]:
    conn = _get_db(db_path)
    if conn is None:
        return []
    try:
        return _rows(
            conn,
            "SELECT * FROM state_events WHERE id > ? ORDER BY id",
            (since,),
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTML pages
# ---------------------------------------------------------------------------

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>red-run state viewer - login</title>
<style>
:root { --bg: #0d1117; --bg2: #161b22; --border: #30363d; --text: #c9d1d9;
  --dim: #8b949e; --accent: #58a6ff; --red: #f85149; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
  font-size: 13px; background: var(--bg); color: var(--text);
  display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.login-box { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; padding: 32px; width: 400px; }
h1 { font-size: 16px; color: var(--accent); margin-bottom: 16px; }
label { display: block; color: var(--dim); font-size: 11px;
  text-transform: uppercase; margin-bottom: 6px; }
input[type="password"] { width: 100%; background: var(--bg); border: 1px solid var(--border);
  border-radius: 4px; padding: 8px 10px; color: var(--text); font-family: inherit;
  font-size: 13px; margin-bottom: 16px; }
button { background: var(--accent); color: #000; border: none; border-radius: 4px;
  padding: 8px 20px; font-family: inherit; font-size: 13px; cursor: pointer;
  font-weight: 600; }
button:hover { opacity: 0.9; }
.error { color: var(--red); font-size: 12px; margin-bottom: 12px; display: none; }
</style>
</head>
<body>
<div class="login-box">
  <h1>red-run state viewer</h1>
  <div class="error" id="error">Invalid token</div>
  <form method="POST" action="/login">
    <label for="token">Authentication Token</label>
    <input type="password" id="token" name="token" placeholder="Paste token here..." autofocus>
    <button type="submit">Authenticate</button>
  </form>
</div>
<script>
if (location.search.includes('fail=1')) document.getElementById('error').style.display='block';
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>red-run state viewer</title>
<style>
:root {
  --bg: #0d1117; --bg2: #161b22; --bg3: #21262d; --border: #30363d;
  --text: #c9d1d9; --dim: #8b949e; --accent: #58a6ff;
  --red: #f85149; --orange: #d29922; --yellow: #e3b341;
  --green: #3fb950; --purple: #bc8cff; --blue: #58a6ff; --gray: #8b949e;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
  font-size: 13px; background: var(--bg); color: var(--text); padding: 16px; }
h1 { font-size: 18px; color: var(--accent); margin-bottom: 4px; }
h2 { font-size: 14px; color: var(--dim); margin: 16px 0 8px; cursor: pointer; user-select: none; }
h2::before { content: '\25BE '; font-size: 10px; }
h2.collapsed::before { content: '\25B8 '; }
.banner { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; padding: 24px; text-align: center; color: var(--dim); margin: 24px 0; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 12px 0; }
.card { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
  padding: 12px 16px; min-width: 120px; }
.card .num { font-size: 24px; font-weight: bold; }
.card .label { color: var(--dim); font-size: 11px; text-transform: uppercase; }
table { width: 100%; border-collapse: collapse; margin: 4px 0 16px; }
th { text-align: left; color: var(--dim); font-size: 11px; text-transform: uppercase;
  padding: 6px 8px; border-bottom: 1px solid var(--border); cursor: pointer; user-select: none; }
th:hover { color: var(--accent); }
td { padding: 6px 8px; border-bottom: 1px solid var(--bg3); max-width: 400px;
  word-break: break-word; cursor: default; vertical-align: top; }
td .cell { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical;
  overflow: hidden; }
tr:hover td { background: var(--bg2); }
.badge { display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 11px; font-weight: 600; }
.sev-critical { background: var(--red); color: #fff; }
.sev-high { background: var(--orange); color: #fff; }
.sev-medium { background: var(--yellow); color: #000; }
.sev-low { background: var(--blue); color: #fff; }
.sev-info { background: var(--gray); color: #fff; }
.status-active { color: var(--green); }
.status-revoked, .status-down, .status-closed { color: var(--dim); text-decoration: line-through; }
.status-exploited { color: var(--green); }
.status-identified { color: var(--yellow); }
.status-blocked { color: var(--red); }
.filter-bar { margin: 12px 0; }
.filter-bar input { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 4px; padding: 6px 10px; color: var(--text); width: 300px; font-family: inherit; }
.section { margin-bottom: 8px; }
.section-body { overflow-x: auto; }
.section-body.hidden { display: none; }
.conn-status { font-size: 11px; padding: 2px 8px; border-radius: 3px; float: right; }
.conn-ok { background: var(--green); color: #000; }
.conn-err { background: var(--red); color: #fff; }
/* Kill-chain graph — Host Card Topology */
#graph-container { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; overflow: hidden; min-height: 200px; margin: 12px 0; position: relative;
  cursor: grab; }
#graph-container.panning { cursor: grabbing; }
#graph-container svg { display: block; user-select: none; -webkit-user-select: none; }
.host-card { cursor: default; }
.host-card-bg { rx: 6; ry: 6; fill: var(--bg2); stroke-width: 2; }
.host-card-header { fill: var(--bg3); }
.card-section-header { font-size: 10px; text-transform: uppercase; fill: var(--dim); font-weight: 600; letter-spacing: 0.5px; }
.card-section-line { stroke: var(--border); stroke-width: 0.5; }
.card-item { font-size: 11px; fill: var(--text); }
.card-item-active { fill: var(--green); }
.card-item-blocked { fill: var(--red); text-decoration: line-through; }
.card-item-pending { fill: var(--yellow); }
@keyframes pulseGlow {
  0%, 100% { filter: drop-shadow(0 0 2px var(--yellow)); }
  50% { filter: drop-shadow(0 0 8px var(--yellow)); }
}
.card-actionable-glow { animation: pulseGlow 2s ease-in-out infinite; }
.node-new { animation: fadeIn 0.5s ease-in; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.card-edge { fill: none; stroke-width: 3; }
.card-edge-active { stroke: var(--green); stroke-dasharray: none; }
.card-edge-pending { stroke: var(--yellow); stroke-dasharray: 6 3; }
.card-edge-blocked { stroke: var(--red); stroke-dasharray: 6 3; }
.card-edge-recon { stroke: var(--dim); stroke-dasharray: 3 4; stroke-width: 1; opacity: 0.5; }
.edge-label { font-size: 9px; pointer-events: none; }
.graph-legend { position: absolute; bottom: 6px; left: 6px; right: 6px;
  background: var(--bg2); border-top: 1px solid var(--border); padding: 4px 8px;
  font-size: 10px; color: var(--text); display: flex; gap: 8px; align-items: center;
  flex-wrap: wrap; z-index: 5; pointer-events: none; }
.graph-legend .legend-dim { color: var(--dim); font-weight: 600; }
.graph-legend .legend-item { display: inline-flex; align-items: center; gap: 4px; }
.tooltip { position: absolute; background: var(--bg3); border: 1px solid var(--border);
  border-radius: 4px; padding: 6px 10px; font-size: 11px; pointer-events: none;
  display: none; z-index: 10; max-width: 300px; white-space: pre-wrap; }
.refresh-btn { background: var(--bg3); color: var(--dim); border: 1px solid var(--border);
  border-radius: 4px; padding: 3px 10px; font-family: inherit; font-size: 11px;
  cursor: pointer; vertical-align: middle; }
.refresh-btn:hover { color: var(--accent); border-color: var(--accent); }
</style>
</head>
<body>
<h1>red-run state viewer <span class="conn-status conn-ok" id="conn">connected</span></h1>
<div id="banner" class="banner" style="display:none">Waiting for engagement...</div>

<div id="content" style="display:none">
<div class="cards" id="summary-cards"></div>

<div class="section">
  <h2 onclick="toggleSection('graph')">Kill-Chain Graph <button class="refresh-btn" onclick="event.stopPropagation(); refreshAll()">Refresh</button></h2>
  <div id="graph-body" class="section-body">
    <div id="graph-container"><svg id="graph"></svg><div class="tooltip" id="tooltip"></div><div class="graph-legend" id="graph-legend"></div></div>
  </div>
</div>

<div class="filter-bar">
  <input type="text" id="filter" placeholder="Filter across all tables..." oninput="applyFilter()">
  <button class="refresh-btn" onclick="refreshAll()" style="margin-left:8px">Refresh</button>
</div>

<div id="tables"></div>
</div>

<script>
// --- State & SSE ---
let state = null;
let sortState = {}; // tableId -> { col, asc }

let graphDirty = false; // true when state updated via SSE but graph not yet redrawn

const evtSource = new EventSource('/api/stream');
evtSource.onmessage = (e) => {
  const data = JSON.parse(e.data);
  if (data.type === 'state') {
    state = data.payload;
    renderLight(); // cards + tables only, no graph rebuild
    graphDirty = true;
  } else if (data.type === 'events' && data.payload.length && state) {
    const ids = new Set(state.events.map(e => e.id));
    for (const ev of data.payload) { if (!ids.has(ev.id)) state.events.unshift(ev); }
    state.events = state.events.slice(0, 200);
    renderLight();
    graphDirty = true;
  }
  setConn(true);
};
evtSource.onerror = () => setConn(false);

function refreshAll() {
  fetch('/api/state').then(r=>r.json()).then(d => { state = d; render(); graphDirty = false; });
}

function setConn(ok) {
  const el = document.getElementById('conn');
  el.textContent = ok ? 'connected' : 'disconnected';
  el.className = 'conn-status ' + (ok ? 'conn-ok' : 'conn-err');
}

// --- Rendering ---
function showContent() {
  if (!state) return;
  const hasData = state.targets.length || state.vulns.length || state.credentials.length;
  document.getElementById('banner').style.display = (state.engagement || hasData) ? 'none' : 'block';
  document.getElementById('content').style.display = (state.engagement || hasData) ? '' : 'none';
}
function render() {
  showContent();
  renderCards();
  renderGraph();
  renderTables();
}
function renderLight() {
  showContent();
  renderCards();
  renderTables();
}

function renderCards() {
  const c = document.getElementById('summary-cards');
  const actionableVulns = state.vulns.filter(v => v.status === 'found');
  const exploitedVulns = state.vulns.filter(v => v.status === 'exploited');
  const sevCounts = {};
  actionableVulns.forEach(v => { sevCounts[v.severity] = (sevCounts[v.severity]||0) + 1; });
  const sevStr = ['critical','high','medium','low','info']
    .filter(s => sevCounts[s]).map(s => `${sevCounts[s]} ${s}`).join(', ') || 'none';
  c.innerHTML = [
    card(state.targets.length, 'Targets'),
    card(state.credentials.length, 'Credentials'),
    card(state.access.filter(a=>a.active).length, 'Active Access'),
    card(actionableVulns.length, 'Actionable', sevStr),
    card(exploitedVulns.length, 'Exploited'),
    card(state.pivot_map.length, 'Pivots'),
    card(state.tunnels.filter(t=>t.status==='active').length, 'Tunnels'),
    card(state.blocked.length, 'Blocked'),
  ].join('');
}
function card(num, label, sub) {
  return `<div class="card"><div class="num">${num}</div><div class="label">${label}</div>${sub?`<div class="label">${sub}</div>`:''}</div>`;
}

// --- Tables ---
const TABLE_DEFS = [
  { id: 'targets', title: 'Targets', key: 'targets',
    cols: ['host','os','role','ports','notes'],
    fmt: { ports: r => (r.ports||[]).map(p=>`${p.port}/${p.protocol} ${p.service}`).join(', ') }},
  { id: 'credentials', title: 'Credentials', key: 'credentials',
    cols: ['domain','username','secret_type','secret','cracked','source','tested'],
    fmt: { secret: r => r.secret || '',
           cracked: r => r.cracked ? 'yes' : '',
           tested: r => (r.tested_against||[]).map(t=>`${t.host}/${t.service}:${t.works?'OK':'FAIL'}`).join(', ') }},
  { id: 'access', title: 'Access', key: 'access',
    cols: ['host','username','access_type','privilege','method','active','session_ref'],
    fmt: { active: r => `<span class="status-${r.active?'active':'revoked'}">${r.active?'active':'revoked'}</span>` }},
  { id: 'vulns', title: 'Vulns', key: 'vulns',
    cols: ['title','severity','status','host','vuln_type','details'],
    fmt: { severity: r => `<span class="badge sev-${r.severity}">${r.severity}</span>`,
           details: r => r.details || '' }},
  { id: 'pivot_map', title: 'Pivot Map', key: 'pivot_map',
    cols: ['source','destination','method','status'],
    fmt: { status: r => `<span class="status-${r.status}">${r.status}</span>` }},
  { id: 'tunnels', title: 'Tunnels', key: 'tunnels',
    cols: ['tunnel_type','pivot_host','target_subnet','local_endpoint','remote_endpoint','requires_proxychains','status'],
    fmt: { requires_proxychains: r => r.requires_proxychains ? 'yes' : '',
           status: r => `<span class="status-${r.status}">${r.status}</span>` }},
  { id: 'blocked', title: 'Blocked', key: 'blocked',
    cols: ['technique','host','reason','retry'],
    fmt: {}},
  { id: 'events', title: 'Event Timeline', key: 'events',
    cols: ['created_at','event_type','agent','summary'],
    fmt: { event_type: r => `<span class="badge sev-info">${r.event_type}</span>`,
           agent: r => r.agent ? `<span class="badge sev-low">${r.agent}</span>` : '' }},
];

function renderTables() {
  const container = document.getElementById('tables');
  const filter = document.getElementById('filter').value.toLowerCase();
  let html = '';
  for (const def of TABLE_DEFS) {
    let rows = state[def.key] || [];
    if (filter) {
      rows = rows.filter(r => JSON.stringify(r).toLowerCase().includes(filter));
    }
    // Sort
    const ss = sortState[def.id];
    if (ss) {
      const col = ss.col;
      rows = [...rows].sort((a,b) => {
        let va = getCellValue(a, col, def), vb = getCellValue(b, col, def);
        if (va < vb) return ss.asc ? -1 : 1;
        if (va > vb) return ss.asc ? 1 : -1;
        return 0;
      });
    }
    const collapsed = document.querySelector(`#section-${def.id} h2`)?.classList.contains('collapsed');
    html += `<div class="section" id="section-${def.id}">`;
    html += `<h2 onclick="toggleSection('${def.id}')" class="${collapsed?'collapsed':''}">${def.title} (${rows.length})</h2>`;
    html += `<div class="section-body${collapsed?' hidden':''}">`;
    html += '<table><thead><tr>';
    for (const col of def.cols) {
      const arrow = ss && ss.col === col ? (ss.asc ? ' \u25B4' : ' \u25BE') : '';
      html += `<th onclick="sortTable('${def.id}','${col}')">${col}${arrow}</th>`;
    }
    html += '</tr></thead><tbody>';
    for (const row of rows) {
      html += '<tr>';
      for (const col of def.cols) {
        const fmt = def.fmt[col];
        const val = fmt ? fmt(row) : (row[col] ?? '');
        const raw = row[col];
        const tip = (raw != null && typeof raw !== 'object') ? String(raw) : String(val).replace(/<[^>]*>/g, '');
        html += `<td><div class="cell" data-tip="${tip.replace(/"/g,'&quot;')}">${val}</div></td>`;
      }
      html += '</tr>';
    }
    if (!rows.length) html += `<tr><td colspan="${def.cols.length}" style="color:var(--dim);text-align:center">No data</td></tr>`;
    html += '</tbody></table></div></div>';
  }
  container.innerHTML = html;
}

// Show tooltip when cell content is clipped (by line-clamp or JS truncation)
document.addEventListener('mouseenter', e => {
  const cell = e.target.closest('.cell[data-tip]');
  if (!cell) return;
  const td = cell.parentElement;
  const tip = cell.dataset.tip;
  const visible = cell.textContent;
  // Check 1: JS formatter truncated the text (tip is longer than displayed)
  if (tip.length > visible.length + 3) { td.title = tip; return; }
  // Check 2: CSS line-clamp is hiding lines
  cell.style.webkitLineClamp = 'unset';
  const full = cell.scrollHeight;
  cell.style.webkitLineClamp = '';
  td.title = (full > cell.clientHeight + 2) ? tip : '';
}, true);

function getCellValue(row, col, def) {
  const fmt = def.fmt[col];
  if (fmt) { const v = fmt(row); return typeof v === 'string' ? v.replace(/<[^>]*>/g,'') : v; }
  return row[col] ?? '';
}

function sortTable(tableId, col) {
  const cur = sortState[tableId];
  if (cur && cur.col === col) { cur.asc = !cur.asc; }
  else { sortState[tableId] = { col, asc: true }; }
  renderTables();
}

function toggleSection(id) {
  const h = document.querySelector(`#section-${id} h2`) || document.querySelector(`#${id}-body`)?.previousElementSibling;
  if (!h) return;
  h.classList.toggle('collapsed');
  const body = h.nextElementSibling || document.getElementById(`${id}-body`);
  if (body) body.classList.toggle('hidden');
}

function applyFilter() { renderTables(); }

// --- Kill-Chain Graph (Host Card Topology) ---
function renderGraph() {
  const svg = document.getElementById('graph');
  const container = document.getElementById('graph-container');
  if (!state || (!state.targets.length && !state.vulns.length)) {
    svg.innerHTML = '<text x="50%" y="50" text-anchor="middle" fill="#8b949e" font-size="13">No data for graph</text>';
    svg.setAttribute('width', container.clientWidth);
    svg.setAttribute('height', 100);
    return;
  }

  // --- Helpers ---
  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function escAttr(s) { return esc(s).replace(/"/g,'&quot;'); }
  function trunc(s, max) { s = String(s||''); return s.length > max ? s.slice(0, max-1)+'\u2026' : s; }

  const providedPattern = /\b(provided|scope|pre-engagement|given|initial|pentest|operator)\b/i;
  const targetHosts = state.targets.map(t => t.host);

  // --- Build per-host data ---
  // Provided credentials
  const providedCreds = state.credentials.filter(c => c.source && providedPattern.test(c.source));
  const providedCredUsernames = new Set(providedCreds.map(c => c.username));

  // Access by host
  const accessByHost = {};
  for (const a of state.access) {
    if (!accessByHost[a.host]) accessByHost[a.host] = [];
    accessByHost[a.host].push(a);
  }

  // Creds associated with each host via multiple heuristics
  const credsByHost = {};
  for (const c of state.credentials) {
    if (providedPattern.test(c.source || '')) continue; // skip provided creds
    let assigned = false;
    // 1. via_access_id links to an access record on a host
    if (c.via_access_id) {
      const linkedAccess = state.access.find(a => a.id === c.via_access_id);
      if (linkedAccess) {
        if (!credsByHost[linkedAccess.host]) credsByHost[linkedAccess.host] = [];
        credsByHost[linkedAccess.host].push(c);
        assigned = true;
      }
    }
    // 2. source mentions a host
    if (!assigned && c.source) {
      for (const h of targetHosts) {
        if (c.source.includes(h)) {
          if (!credsByHost[h]) credsByHost[h] = [];
          credsByHost[h].push(c);
          assigned = true;
          break;
        }
      }
    }
    // 3. discovered_by agent working on a host (match agent name to access host)
    if (!assigned && c.discovered_by) {
      for (const h of targetHosts) {
        if (c.discovered_by.includes(h)) {
          if (!credsByHost[h]) credsByHost[h] = [];
          credsByHost[h].push(c);
          assigned = true;
          break;
        }
      }
    }
    // 4. tested_against with works=true
    if (!assigned) {
      for (const ta of (c.tested_against || [])) {
        if (ta.works && ta.host) {
          if (!credsByHost[ta.host]) credsByHost[ta.host] = [];
          credsByHost[ta.host].push(c);
          assigned = true;
          break;
        }
      }
    }
  }

  // Vulns by host (all statuses)
  // Orphaned vulns (target_id=NULL, host=unknown) get assigned to the sole
  // target when there's exactly one — avoids invisible vulns on the graph.
  const allVulnsByHost = {};
  const soleHost = targetHosts.length === 1 ? targetHosts[0] : null;
  for (const v of state.vulns) {
    let h = v.host || 'unknown';
    if (h === 'unknown' && soleHost) h = soleHost;
    if (!allVulnsByHost[h]) allVulnsByHost[h] = [];
    allVulnsByHost[h].push(v);
  }

  // Blocked by host
  const blockedByHost = {};
  for (const b of state.blocked) {
    let h = b.host || 'unknown';
    if (h === 'unknown' && soleHost) h = soleHost;
    if (!blockedByHost[h]) blockedByHost[h] = [];
    blockedByHost[h].push(b);
  }

  // Pivots: parse source/dest to host names
  const pivotEdges = []; // { srcHost, dstHost, method, status, detail }
  const pivotDestHosts = new Set();
  for (const p of state.pivot_map) {
    let srcHost = null;
    if (targetHosts.includes(p.source)) {
      srcHost = p.source;
    } else {
      for (const h of targetHosts) {
        if (p.source.includes(h)) { srcHost = h; break; }
      }
    }
    // Fall back: find access on source host
    if (!srcHost) {
      for (const a of state.access) {
        if (a.active && (a.host === p.source || p.source.includes(a.host))) {
          srcHost = a.host; break;
        }
      }
    }
    let dstHost = null;
    if (targetHosts.includes(p.destination)) {
      dstHost = p.destination;
    } else {
      for (const h of targetHosts) {
        if (p.destination.includes(h)) { dstHost = h; break; }
        const prefix = h.split('.').slice(0,3).join('.');
        if (p.destination.includes(prefix + '.')) { dstHost = h; break; }
      }
    }
    if (srcHost && dstHost) {
      const methodShort = trunc((p.method || 'pivot').split(/[.\-,]/)[0].trim(), 30);
      pivotEdges.push({ srcHost, dstHost, method: methodShort, status: p.status,
        detail: `${p.method || 'pivot'} (${p.status})` });
      pivotDestHosts.add(dstHost);
    }
  }

  // Hosts reached via provided creds (access records OR successful tested_against)
  const hostsViaProvidedCred = new Set();
  for (const a of state.access) {
    if (providedCredUsernames.has(a.username)) {
      hostsViaProvidedCred.add(a.host);
    }
  }
  for (const c of providedCreds) {
    for (const t of (c.tested_against || [])) {
      if (t.works) hostsViaProvidedCred.add(t.host);
    }
  }

  // --- Column assignment ---
  // Col 0: attacker
  // Col 1: hosts directly reachable (not pivot destinations, OR reached via provided creds)
  // Col 2+: hosts only reachable via pivots from col N-1
  const hostCol = {};
  const col1Hosts = [];
  const remainHosts = [];
  for (const t of state.targets) {
    if (!pivotDestHosts.has(t.host)) {
      hostCol[t.host] = 1;
      col1Hosts.push(t.host);
    } else {
      remainHosts.push(t.host);
    }
  }
  // BFS through pivots for deeper columns
  let frontier = new Set(col1Hosts);
  let curCol = 1;
  while (remainHosts.length && curCol < 10) {
    const nextFrontier = new Set();
    for (let i = remainHosts.length - 1; i >= 0; i--) {
      const h = remainHosts[i];
      const reachable = pivotEdges.some(pe => pe.dstHost === h && frontier.has(pe.srcHost));
      if (reachable) {
        hostCol[h] = curCol + 1;
        nextFrontier.add(h);
        remainHosts.splice(i, 1);
      }
    }
    if (nextFrontier.size === 0) break;
    frontier = nextFrontier;
    curCol++;
  }
  // Any remaining go to col 1
  for (const h of remainHosts) { hostCol[h] = 1; }

  // --- Build actionable items per host ---
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  function getActionable(host) {
    const items = [];
    // Vulns not exploited and not blocked with retry=no
    const blockedTechniques = new Set((blockedByHost[host] || []).filter(b => b.retry === 'no').map(b => b.technique));
    for (const v of (allVulnsByHost[host] || []).slice().sort((a,b) => (sevOrder[a.severity]??9) - (sevOrder[b.severity]??9))) {
      if (v.status === 'found' && v.severity !== 'info' && !blockedTechniques.has(v.title)) {
        const sevColor = v.severity === 'critical' ? '#f85149' : v.severity === 'high' ? '#d29922' : '#8b949e';
        items.push({ icon: '\u26A0', text: v.title, detail: `${v.severity} | ${v.status}\n${v.details||''}`, color: sevColor });
      }
    }
    // Uncracked hashes
    for (const c of (credsByHost[host] || [])) {
      if (!c.cracked && c.secret_type !== 'password' && c.secret_type !== 'plaintext') {
        const label = c.domain ? `${c.domain}\\${c.username}` : c.username;
        items.push({ icon: '#', text: `${label} (${c.secret_type}, uncracked)`, detail: `source: ${c.source}` });
      }
    }
    // Identified pivots originating from this host
    for (const pe of pivotEdges) {
      if (pe.srcHost === host && pe.status === 'identified') {
        items.push({ icon: '\u2192', text: `Pivot to ${pe.dstHost}: ${pe.method}`, detail: pe.detail });
      }
    }
    return items;
  }

  // --- Card content builder (returns { html, height }) ---
  const CARD_W = 280;
  const CARD_PAD = 10;
  const HEADER_H = 38;
  const SECTION_HEADER_H = 18;
  const ITEM_H = 16;
  const SECTION_GAP = 4;
  const MIN_CARD_H = 80;

  function buildCardContent(host, target) {
    let sections = [];

    // ACCESS section
    const accesses = accessByHost[host] || [];
    if (accesses.length) {
      const items = accesses.map(a => {
        const icon = a.active ? '\u2713' : '\u2717';
        const cls = a.active ? 'card-item-active' : 'card-item-blocked';
        const text = `${a.username} (${a.access_type}, ${a.privilege})`;
        const detail = `${a.access_type} | ${a.privilege}\n${a.method}`;
        return { icon, text, cls, detail };
      });
      sections.push({ title: 'ACCESS', items });
    } else {
      sections.push({ title: 'ACCESS', items: [{ icon: '\u2014', text: '(none yet)', cls: 'card-item', detail: '' }] });
    }

    // CREDS FOUND
    const creds = credsByHost[host] || [];
    if (creds.length) {
      const items = creds.map(c => {
        const label = c.domain ? `${c.domain}\\${c.username}` : c.username;
        const icon = c.cracked ? '\u25CF' : '\u25CB';
        const srcBrief = trunc(c.source || '', 25);
        const text = `${label} (${c.secret_type})${srcBrief ? ' \u2190 ' + srcBrief : ''}`;
        const detail = `${c.secret_type}${c.cracked ? ' (cracked)' : ''}\nsource: ${c.source}`;
        return { icon, text, cls: 'card-item', detail };
      });
      sections.push({ title: 'CREDS FOUND', items });
    }

    // EXPLOITED — successfully exploited vulns (above actionable = "done" first)
    const exploitedVulns = (allVulnsByHost[host] || []).filter(v => v.status === 'exploited');
    if (exploitedVulns.length) {
      const items = exploitedVulns.map(v => {
        const text = v.title;
        const detail = `${v.severity} | exploited\n${v.details||''}`;
        return { icon: '\u2713', text, cls: 'card-item-active', detail, color: '#3fb950' };
      });
      sections.push({ title: 'EXPLOITED', items });
    }

    // ACTIONABLE — found vulns (not blocked), uncracked hashes, identified pivots
    const actionable = getActionable(host);
    if (actionable.length) {
      sections.push({ title: 'ACTIONABLE', items: actionable.map(a => ({
        icon: a.icon, text: a.text, cls: 'card-item-pending', detail: a.detail,
        color: a.color
      })), glow: true });
    }

    // Calculate height
    let h = HEADER_H;
    for (const s of sections) {
      h += SECTION_HEADER_H + s.items.length * ITEM_H + SECTION_GAP;
    }
    h = Math.max(MIN_CARD_H, h + CARD_PAD);

    return { sections, height: h };
  }

  // --- Build card data ---
  const cards = []; // { id, host, col, label, subtitle, borderColor, sections, height, x, y, w }

  // Attacker card
  const attackerSections = [];
  if (providedCreds.length) {
    attackerSections.push({ title: 'PROVIDED CREDS', items: providedCreds.map(c => {
      const label = c.domain ? `${c.domain}\\${c.username}` : c.username;
      return { icon: '\u25CF', text: `${label} (${c.secret_type})`, cls: 'card-item', detail: `source: ${c.source}` };
    }) });
  }
  let attackerH = HEADER_H;
  for (const s of attackerSections) { attackerH += SECTION_HEADER_H + s.items.length * ITEM_H + SECTION_GAP; }
  attackerH = attackerSections.length ? Math.max(MIN_CARD_H, attackerH + CARD_PAD) : HEADER_H + 4;
  const ATTACKER_W = attackerSections.length ? CARD_W : 120;

  cards.push({
    id: 'attacker', host: null, col: 0,
    label: 'ATTACKER', subtitle: '',
    borderColor: '#f85149',
    sections: attackerSections, height: attackerH,
    x: 0, y: 0, w: ATTACKER_W
  });

  // Host cards
  for (const t of state.targets) {
    const col = hostCol[t.host] || 1;
    const hasActiveAccess = (accessByHost[t.host] || []).some(a => a.active);
    const actionable = getActionable(t.host);
    let borderColor = '#58a6ff'; // discovered
    if (hasActiveAccess) borderColor = '#3fb950';
    else if (actionable.length) borderColor = '#e3b341';

    // Resolve hostname and IP for display
    // Sources: host field, notes, port banners (LDAP often has "Hostname: X")
    const hostIsIP = /^\d+\.\d+\.\d+\.\d+$/.test(t.host);
    let hostname = '';
    let ip = '';

    // Collect all text to search: notes + port banners
    const searchText = [t.notes || ''];
    for (const p of (t.ports || [])) {
      if (p.banner) searchText.push(p.banner);
    }
    const allText = searchText.join(' | ');

    if (hostIsIP) {
      ip = t.host;
      // Try "Hostname: X" from banners first (most reliable)
      const hnMatch = allText.match(/[Hh]ostname:\s*([A-Za-z0-9_-]+)/);
      if (hnMatch) {
        // Combine with domain if available
        const domMatch = allText.match(/[Dd]omain:\s*([A-Za-z0-9._-]+\.[a-z]{2,})/);
        hostname = domMatch ? `${hnMatch[1]}.${domMatch[1]}` : hnMatch[1];
      } else {
        // Fall back to FQDN pattern in notes (e.g., "DC01.pirate.htb")
        const fqdnMatch = allText.match(/\b([A-Za-z][A-Za-z0-9_-]*\.[A-Za-z0-9._-]+\.[a-z]{2,})\b/);
        if (fqdnMatch) hostname = fqdnMatch[1];
      }
    } else {
      hostname = t.host;
      // Extract IP from notes/banners
      const ipMatch = allText.match(/(?:IP|ip)[:\s]*(\d+\.\d+\.\d+\.\d+)/);
      if (ipMatch) ip = ipMatch[1];
      else {
        const anyIP = allText.match(/(\d+\.\d+\.\d+\.\d+)/);
        if (anyIP) ip = anyIP[1];
      }
    }

    // Label: "HOSTNAME (IP)" or just one if the other is missing
    const headerLabel = hostname && ip ? `${hostname} (${ip})`
                      : hostname ? hostname : ip;
    const subtitle = [t.os, t.role].filter(Boolean).join(' \u00B7 ');

    const { sections, height } = buildCardContent(t.host, t);

    cards.push({
      id: `host:${t.host}`, host: t.host, col,
      label: headerLabel, subtitle,
      borderColor,
      sections, height,
      x: 0, y: 0, w: CARD_W
    });
  }

  // --- Layout: columns ---
  const COL_GAP = 180;
  const ROW_GAP = 30;
  const PAD = 40;

  const maxCol = Math.max(...cards.map(c => c.col));
  const columns = {};
  for (const c of cards) {
    if (!columns[c.col]) columns[c.col] = [];
    columns[c.col].push(c);
  }

  // Position cards within columns
  const colHeights = {};
  for (let col = 0; col <= maxCol; col++) {
    const group = columns[col] || [];
    let y = PAD;
    for (const card of group) {
      card.x = PAD + col * (CARD_W + COL_GAP);
      card.y = y;
      y += card.height + ROW_GAP;
    }
    colHeights[col] = y - ROW_GAP + PAD;
  }

  // Vertically center columns relative to tallest
  const maxColHeight = Math.max(...Object.values(colHeights));
  for (let col = 0; col <= maxCol; col++) {
    const group = columns[col] || [];
    const offset = (maxColHeight - (colHeights[col] || 0)) / 2;
    for (const card of group) {
      card.y += offset;
    }
  }

  // --- Build edges ---
  const graphEdges = []; // { srcCard, dstCard, label, edgeClass, detail }
  const cardById = {};
  for (const c of cards) cardById[c.id] = c;

  // Helper: extract short label for edge pill from method text.
  // Two tiers: access mechanism (how you interact) before transport/delivery
  // (how it got there). "PHP webshell via SMB write" → "webshell" not "smb".
  function shortEdgeLabel(text) {
    if (!text) return '';
    const t = text.toLowerCase();
    // Tier 1: access mechanism — what the attacker interacts with
    if (t.includes('webshell') || t.includes('web shell') || t.includes('cmd.php') || t.includes('cmd.aspx') || t.includes('cmd.jsp')) return 'webshell';
    if (t.includes('reverse shell') || t.includes('rev shell') || t.includes('revshell')) return 'revshell';
    if (t.includes('winrm') || t.includes('evil-winrm')) return 'winrm';
    if (t.includes('psexec')) return 'psexec';
    if (t.includes('wmiexec') || t.includes('wmi')) return 'wmi';
    if (t.includes('dcom')) return 'dcom';
    if (t.includes('rdp')) return 'rdp';
    if (t.includes('ssh') && !t.includes('ssh tunnel') && !t.includes('ssh -')) return 'ssh';
    // Tier 2: transport/delivery/technique
    if (t.includes('chisel')) return 'chisel';
    if (t.includes('ligolo')) return 'ligolo';
    if (t.includes('sshuttle')) return 'sshuttle';
    if (t.includes('ssh tunnel') || t.includes('ssh -')) return 'ssh tunnel';
    if (t.includes('smb')) return 'smb';
    if (t.includes('dns record') || t.includes('dns')) return 'dns';
    if (t.includes('constrained delegation') || t.includes('s4u')) return 'delegation';
    if (t.includes('kerberoast') || t.includes('tgs')) return 'kerberoast';
    if (t.includes('crack')) return 'crack';
    if (t.includes('tunnel') || t.includes('socks')) return 'tunnel';
    if (t.includes('relay')) return 'relay';
    if (t.includes('pivot')) return 'pivot';
    if (t.includes('recon') || t.includes('discover')) return 'recon';
    // Fall back: skip hostnames/IPs/filler, take first method-like word
    const words = text.split(/[\s(,]+/);
    for (const w of words) {
      if (/^\d+\.\d+/.test(w)) continue;
      if (/^[A-Z0-9_-]+\./i.test(w)) continue;
      if (/^(the|a|an|on|in|to|via|from|for|has|need|with)$/i.test(w)) continue;
      return w.slice(0, 12);
    }
    return 'pivot';
  }

  // Map access_type enum to display label. Specific types are used directly;
  // generic types (shell, other) fall through to method text parsing.
  const accessTypeLabels = {
    web_shell: 'webshell', ssh: 'ssh', winrm: 'winrm', rdp: 'rdp',
    db: 'db', token: 'token', vpn: 'vpn'
  };

  // Attacker -> hosts with access via provided creds
  for (const h of hostsViaProvidedCred) {
    const dst = cardById[`host:${h}`];
    if (!dst) continue;
    const accOnHost = (accessByHost[h] || []).find(a => providedCredUsernames.has(a.username));
    if (accOnHost) {
      graphEdges.push({ srcCard: cardById['attacker'], dstCard: dst,
        shortLabel: accessTypeLabels[accOnHost.access_type] || shortEdgeLabel(accOnHost.method) || accOnHost.access_type, edgeClass: 'card-edge-active',
        detail: `${accOnHost.username} (${accOnHost.access_type})\nMethod: ${accOnHost.method}` });
    } else {
      let shortLabel = 'auth';
      let detail = 'Authenticated via provided credential';
      for (const c of providedCreds) {
        const tested = (c.tested_against || []).find(t => t.host === h && t.works);
        if (tested) {
          shortLabel = tested.service;
          detail = `${c.username} via ${tested.service}`;
          break;
        }
      }
      graphEdges.push({ srcCard: cardById['attacker'], dstCard: dst,
        shortLabel, edgeClass: 'card-edge-active', detail });
    }
  }

  // Attacker -> hosts discovered but no access via provided creds (recon)
  for (const t of state.targets) {
    if (hostsViaProvidedCred.has(t.host)) continue;
    if (pivotDestHosts.has(t.host)) continue;
    const dst = cardById[`host:${t.host}`];
    if (!dst) continue;
    const activeAccess = (accessByHost[t.host] || []).filter(a => a.active);
    if (activeAccess.length) {
      const acc = activeAccess[0];
      const label = accessTypeLabels[acc.access_type] || shortEdgeLabel(acc.method) || acc.access_type || 'access';
      const detail = `${acc.username} (${acc.access_type}, ${acc.privilege})\n${acc.method}`;
      graphEdges.push({ srcCard: cardById['attacker'], dstCard: dst,
        shortLabel: label, edgeClass: 'card-edge-active', detail });
    } else {
      graphEdges.push({ srcCard: cardById['attacker'], dstCard: dst,
        shortLabel: '', edgeClass: 'card-edge-recon', detail: 'Discovered via recon' });
    }
  }

  // Pivot edges — deduplicate: if an exploited pivot exists between two hosts,
  // skip identified pivots between the same pair (they're superseded)
  const exploitedPivotPairs = new Set();
  for (const pe of pivotEdges) {
    if (pe.status === 'exploited') exploitedPivotPairs.add(`${pe.srcHost}|${pe.dstHost}`);
  }
  for (const pe of pivotEdges) {
    const src = cardById[`host:${pe.srcHost}`];
    const dst = cardById[`host:${pe.dstHost}`];
    if (!src || !dst) continue;
    // Skip identified/pending pivots when an exploited pivot already covers this pair
    if (pe.status !== 'exploited' && exploitedPivotPairs.has(`${pe.srcHost}|${pe.dstHost}`)) continue;
    let edgeClass = 'card-edge-pending';
    if (pe.status === 'exploited') edgeClass = 'card-edge-active';
    else if (pe.status === 'blocked') edgeClass = 'card-edge-blocked';
    graphEdges.push({ srcCard: src, dstCard: dst,
      shortLabel: shortEdgeLabel(pe.method), edgeClass, detail: pe.detail });
  }

  // --- SVG dimensions ---
  const svgW = PAD * 2 + (maxCol + 1) * CARD_W + maxCol * COL_GAP;
  const svgH = Math.max(200, maxColHeight);
  const totalW = Math.max(svgW, 700);
  const totalH = svgH;

  // --- Render SVG ---
  let svgHtml = '<defs></defs>';

  // Draw cards first
  for (const card of cards) {
    const isActionable = card.sections.some(s => s.glow);
    const gCls = 'host-card node-new' + (isActionable ? ' card-actionable-glow' : '');

    svgHtml += `<g class="${gCls}">`;

    // Card background with left border accent
    svgHtml += `<rect class="host-card-bg" x="${card.x}" y="${card.y}" width="${card.w}" height="${card.height}" stroke="${card.borderColor}"/>`;
    // Left accent bar
    svgHtml += `<rect x="${card.x}" y="${card.y}" width="4" height="${card.height}" rx="2" fill="${card.borderColor}"/>`;

    // Header background
    svgHtml += `<rect class="host-card-header" x="${card.x + 4}" y="${card.y}" width="${card.w - 4}" height="${HEADER_H}" rx="0"/>`;
    // Top-right corner rounding for header
    svgHtml += `<rect class="host-card-header" x="${card.x + 4}" y="${card.y}" width="${card.w - 10}" height="${HEADER_H}" rx="0"/>`;
    svgHtml += `<rect x="${card.x + card.w - 6}" y="${card.y}" width="6" height="6" rx="6" fill="var(--bg3)"/>`;

    // Header text via foreignObject
    svgHtml += `<foreignObject x="${card.x + 10}" y="${card.y + 4}" width="${card.w - 20}" height="${HEADER_H - 4}">`;
    svgHtml += `<div xmlns="http://www.w3.org/1999/xhtml" style="font-size:12px;font-weight:700;color:#c9d1d9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:inherit;">${esc(card.label)}</div>`;
    if (card.subtitle) {
      svgHtml += `<div xmlns="http://www.w3.org/1999/xhtml" style="font-size:10px;color:#8b949e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:inherit;">${esc(card.subtitle)}</div>`;
    }
    svgHtml += `</foreignObject>`;

    // Sections
    let curY = card.y + HEADER_H + 4;
    for (const section of card.sections) {
      // Section header line
      svgHtml += `<line class="card-section-line" x1="${card.x + 10}" y1="${curY}" x2="${card.x + card.w - 10}" y2="${curY}"/>`;
      curY += 3;
      svgHtml += `<text class="card-section-header" x="${card.x + 12}" y="${curY + 10}">${esc(section.title)}</text>`;
      curY += SECTION_HEADER_H;

      // Items via foreignObject for text wrapping
      const itemsH = section.items.length * ITEM_H;
      svgHtml += `<foreignObject x="${card.x + 10}" y="${curY}" width="${card.w - 20}" height="${itemsH + 4}">`;
      svgHtml += `<div xmlns="http://www.w3.org/1999/xhtml" style="font-family:inherit;">`;
      for (const item of section.items) {
        const cls = item.cls || 'card-item';
        let color = '#c9d1d9';
        if (cls === 'card-item-active') color = '#3fb950';
        else if (cls === 'card-item-blocked') color = '#f85149';
        else if (cls === 'card-item-pending') color = '#e3b341';
        if (item.color) color = item.color;
        const decoration = cls === 'card-item-blocked' ? 'line-through' : 'none';
        const truncText = trunc(item.text, 35);
        const detailAttr = escAttr(item.detail || item.text);
        svgHtml += `<div data-detail="${detailAttr}" onmouseenter="showTip(event)" onmouseleave="hideTip()" style="font-size:11px;color:${color};text-decoration:${decoration};white-space:nowrap;overflow:hidden;text-overflow:ellipsis;height:${ITEM_H}px;line-height:${ITEM_H}px;cursor:default;font-family:inherit;">${esc(item.icon)} ${esc(truncText)}</div>`;
      }
      svgHtml += `</div></foreignObject>`;
      curY += itemsH + SECTION_GAP;
    }

    svgHtml += `</g>`;
  }

  // --- Edges (paths, arrows, labels — all drawn after cards so they render on top) ---
  for (const e of graphEdges) {
    const sc = e.srcCard, dc = e.dstCard;
    if (!sc || !dc) continue;
    const sx = sc.x + sc.w;
    const sy = sc.y + sc.height / 2;
    const dx = dc.x;
    const dy = dc.y + dc.height / 2;
    const mx1 = sx + (dx - sx) * 0.4;
    const mx2 = sx + (dx - sx) * 0.6;
    const path = `M${sx},${sy} C${mx1},${sy} ${mx2},${dy} ${dx},${dy}`;

    // Edge path
    const detailAttr = escAttr(e.detail);
    svgHtml += `<path class="card-edge ${e.edgeClass}" d="${path}" data-detail="${detailAttr}" onmouseenter="showTip(evt)" onmouseleave="hideTip()"/>`;

    // Arrowhead
    const arrowSize = 6;
    svgHtml += `<polygon points="${dx},${dy} ${dx-arrowSize},${dy-arrowSize/2} ${dx-arrowSize},${dy+arrowSize/2}" fill="${getEdgeColor(e.edgeClass)}" opacity="${e.edgeClass==='card-edge-recon'?'0.5':'1'}"/>`;

    // Edge label pill (short label, full detail on hover)
    if (e.shortLabel) {
      const lx = (sx + dx) / 2;
      const ly = (sy + dy) / 2;
      const pillText = e.shortLabel;
      const pillW = pillText.length * 7 + 14;
      const pillH = 18;
      const edgeCol = getEdgeColor(e.edgeClass);
      const detailAttr = escAttr(e.detail);
      svgHtml += `<g data-detail="${detailAttr}" onmouseenter="showTip(evt)" onmouseleave="hideTip()" style="cursor:default">`;
      svgHtml += `<rect x="${lx - pillW/2}" y="${ly - pillH/2}" width="${pillW}" height="${pillH}" rx="${pillH/2}" fill="#0d1117" stroke="${edgeCol}" stroke-width="1.5"/>`;
      svgHtml += `<text x="${lx}" y="${ly + 4}" text-anchor="middle" font-size="10" fill="${edgeCol}" font-weight="600">${esc(pillText)}</text>`;
      svgHtml += `</g>`;
    }
  }

  // --- Legend (HTML overlay, not in SVG) ---
  const legendEl = document.getElementById('graph-legend');
  legendEl.innerHTML = [
    '<span class="legend-dim">CARDS</span>',
    ...[ ['#3fb950','Has Access'], ['#e3b341','Actionable'], ['#58a6ff','Discovered'] ].map(
      ([c,l]) => `<span class="legend-item"><span style="display:inline-block;width:12px;height:12px;border:2px solid ${c};border-radius:3px;background:#161b22;"></span>${l}</span>`
    ),
    '<span class="legend-dim" style="margin-left:8px;">EDGES</span>',
    ...[ ['#3fb950','','Active'], ['#e3b341','6 3','Identified'], ['#f85149','6 3','Blocked'] ].map(
      ([c,d,l]) => `<span class="legend-item"><svg width="20" height="12"><line x1="0" y1="6" x2="20" y2="6" stroke="${c}" stroke-width="2"${d?` stroke-dasharray="${d}"`:''}/></svg>${l}</span>`
    ),
  ].join('');

  svg.setAttribute('width', '100%');
  svg.setAttribute('height', Math.max(totalH, container.clientHeight || 400));
  svg.setAttribute('viewBox', `0 0 ${totalW} ${totalH}`);
  svg.innerHTML = svgHtml;

  // --- Zoom & Pan ---
  _setupGraphZoomPan(svg, container, totalW, totalH);
}

function getEdgeColor(cls) {
  if (cls === 'card-edge-active') return '#3fb950';
  if (cls === 'card-edge-pending') return '#e3b341';
  if (cls === 'card-edge-blocked') return '#f85149';
  return '#8b949e';
}

// Zoom/pan state — kept outside renderGraph so it survives re-renders
let _graphVB = null; // { x, y, w, h }
let _graphPanSetup = false;

function _setupGraphZoomPan(svg, container, contentW, contentH) {
  // Initialize or keep current viewBox
  if (!_graphVB) {
    _graphVB = { x: 0, y: 0, w: contentW, h: contentH };
  }
  function applyVB() {
    svg.setAttribute('viewBox', `${_graphVB.x} ${_graphVB.y} ${_graphVB.w} ${_graphVB.h}`);
  }
  applyVB();

  if (_graphPanSetup) return; // listeners already attached
  _graphPanSetup = true;

  // Wheel zoom
  container.addEventListener('wheel', function(ev) {
    ev.preventDefault();
    const rect = svg.getBoundingClientRect();
    const mx = (ev.clientX - rect.left) / rect.width;
    const my = (ev.clientY - rect.top) / rect.height;
    const scale = ev.deltaY > 0 ? 1.12 : 1 / 1.12;
    const nw = _graphVB.w * scale;
    const nh = _graphVB.h * scale;
    _graphVB.x += (_graphVB.w - nw) * mx;
    _graphVB.y += (_graphVB.h - nh) * my;
    _graphVB.w = nw;
    _graphVB.h = nh;
    applyVB();
  }, { passive: false });

  // Mouse drag pan
  let dragging = false, dragStart = null;
  container.addEventListener('mousedown', function(ev) {
    if (ev.button !== 0) return;
    // Don't start pan if clicking inside a card item
    if (ev.target.closest('.host-card')) return;
    dragging = true;
    dragStart = { x: ev.clientX, y: ev.clientY, vx: _graphVB.x, vy: _graphVB.y };
    container.classList.add('panning');
  });
  window.addEventListener('mousemove', function(ev) {
    if (!dragging || !dragStart) return;
    const rect = svg.getBoundingClientRect();
    const dx = (ev.clientX - dragStart.x) / rect.width * _graphVB.w;
    const dy = (ev.clientY - dragStart.y) / rect.height * _graphVB.h;
    _graphVB.x = dragStart.vx - dx;
    _graphVB.y = dragStart.vy - dy;
    applyVB();
  });
  window.addEventListener('mouseup', function() {
    dragging = false;
    dragStart = null;
    container.classList.remove('panning');
  });
}

function showTip(evt) {
  const detail = evt.currentTarget.dataset.detail;
  if (!detail) return;
  const tip = document.getElementById('tooltip');
  tip.textContent = detail;
  tip.style.display = 'block';
  const container = document.getElementById('graph-container');
  const rect = container.getBoundingClientRect();
  // Use clientX/Y minus container rect — works with zoom/pan since
  // tooltip is positioned relative to the container, not the SVG viewBox
  let tx = evt.clientX - rect.left + 12;
  let ty = evt.clientY - rect.top + 12;
  // Keep tooltip inside container bounds
  const tipRect = tip.getBoundingClientRect();
  if (tx + tipRect.width > rect.width - 8) tx = rect.width - tipRect.width - 8;
  if (ty + tipRect.height > rect.height - 8) ty = ty - tipRect.height - 24;
  if (ty < 4) ty = evt.clientY - rect.top + 16; // flip below cursor if clipped at top
  if (tx < 4) tx = 4;
  tip.style.left = tx + 'px';
  tip.style.top = ty + 'px';
}
function hideTip() { document.getElementById('tooltip').style.display = 'none'; }

// Initial fetch
fetch('/api/state').then(r=>r.json()).then(d => { state = d; render(); });
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    db_path: Path = _DEFAULT_DB
    auth_token: str | None = None  # None = no auth required

    def log_message(self, fmt, *args):
        pass

    def _is_authenticated(self) -> bool:
        """Check if request has valid auth (cookie or Bearer header)."""
        if self.auth_token is None:
            return True

        # Check Authorization header (for curl / API clients)
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            candidate = auth_header[7:].strip()
            if hmac.compare_digest(candidate, self.auth_token):
                return True

        # Check session cookie
        cookie_header = self.headers.get("Cookie", "")
        if cookie_header:
            c = cookies.SimpleCookie()
            try:
                c.load(cookie_header)
            except cookies.CookieError:
                return False
            if "session" in c:
                return _verify_session_cookie(c["session"].value, self.auth_token)

        return False

    def _require_auth(self) -> bool:
        """Returns True if request is authenticated. Sends 401/redirect if not."""
        if self._is_authenticated():
            return True
        # For API endpoints, return 401 JSON
        if self.path.startswith("/api/"):
            self._json({"error": "unauthorized"}, 401)
            return False
        # For page requests, redirect to login
        self.send_response(302)
        self.send_header("Location", "/login")
        self.end_headers()
        return False

    def _json(self, data: dict | list, status: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body_str: str, status: int = 200):
        body = body_str.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Login page is always accessible
        if self.path.startswith("/login"):
            if self.auth_token is None:
                # No auth configured, redirect to dashboard
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self._html(LOGIN_HTML)
            return

        if not self._require_auth():
            return

        if self.path == "/":
            self._html(DASHBOARD_HTML)

        elif self.path == "/api/state":
            self._json(_build_state(self.db_path))

        elif self.path.startswith("/api/events"):
            since = 0
            if "since=" in self.path:
                try:
                    since = int(self.path.split("since=")[1].split("&")[0])
                except ValueError:
                    pass
            self._json(_get_events_since(self.db_path, since))

        elif self.path == "/api/stream":
            if not self._is_authenticated():
                self._json({"error": "unauthorized"}, 401)
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            last_full = 0
            last_event_id = 0
            try:
                while True:
                    now = time.time()
                    if now - last_full >= 10:
                        data = _build_state(self.db_path)
                        self.wfile.write(
                            f"data: {json.dumps({'type': 'state', 'payload': data}, default=str)}\n\n".encode()
                        )
                        self.wfile.flush()
                        last_full = now
                        if data["events"]:
                            last_event_id = max(e["id"] for e in data["events"])
                    else:
                        events = _get_events_since(self.db_path, last_event_id)
                        if events:
                            last_event_id = max(e["id"] for e in events)
                            self.wfile.write(
                                f"data: {json.dumps({'type': 'events', 'payload': events}, default=str)}\n\n".encode()
                            )
                            self.wfile.flush()
                    time.sleep(2)
            except (BrokenPipeError, ConnectionResetError):
                pass

        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/login":
            if self.auth_token is None:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return

            # Read form body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode() if content_length else ""

            # Parse token= from application/x-www-form-urlencoded
            submitted = ""
            for part in body.split("&"):
                if part.startswith("token="):
                    submitted = unquote_plus(part[6:])
                    break

            if hmac.compare_digest(submitted, self.auth_token):
                cookie_val = _make_session_cookie(self.auth_token)
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header(
                    "Set-Cookie",
                    f"session={cookie_val}; HttpOnly; SameSite=Strict; Max-Age={_SESSION_MAX_AGE}; Path=/",
                )
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header("Location", "/login?fail=1")
                self.end_headers()
        else:
            self.send_error(404)


def main():
    parser = argparse.ArgumentParser(description="red-run state viewer")
    parser.add_argument(
        "--port", type=int, default=8099, help="Listen port (default: 8099)"
    )
    parser.add_argument("--db", type=str, default=None, help="Path to state.db")
    args = parser.parse_args()

    db_path = Path(args.db) if args.db else _DEFAULT_DB
    Handler.db_path = db_path

    token = _load_token()
    Handler.auth_token = token

    if token:
        bind_addr = "0.0.0.0"
        print(f"auth: token loaded from {_TOKEN_FILE}")
    else:
        bind_addr = "127.0.0.1"
        print("auth: no token file — binding to localhost only (no auth required)")

    server = ThreadingHTTPServer((bind_addr, args.port), Handler)
    print(f"state-dashboard: http://{bind_addr}:{args.port}")
    if bind_addr == "0.0.0.0":
        for ip in _get_local_ips():
            print(f"  remote:     http://{ip}:{args.port}")
        print(
            f"\nIf your VM uses NAT, access via http://localhost:{args.port} on the host"
        )
        print(
            f"after adding a port forwarding rule (host {args.port} -> guest {args.port})."
        )
    print(f"database: {db_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
