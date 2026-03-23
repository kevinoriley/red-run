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


_EMPTY_STATE = {
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


def _build_state(db_path: Path) -> dict:
    """Build full state JSON from all tables."""
    conn = _get_db(db_path)
    if conn is None:
        return _EMPTY_STATE
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
                "SELECT ca.*, t.ip FROM credential_access ca "
                "JOIN targets t ON t.id = ca.target_id "
                "WHERE ca.credential_id = ?",
                (c["id"],),
            )

        access = _rows(
            conn,
            "SELECT a.*, t.ip FROM access a "
            "JOIN targets t ON t.id = a.target_id ORDER BY a.id",
        )
        vulns = _rows(
            conn,
            "SELECT v.*, t.ip FROM vulns v "
            "LEFT JOIN targets t ON t.id = v.target_id ORDER BY v.id",
        )
        pivot_map = _rows(conn, "SELECT * FROM pivot_map ORDER BY id")
        tunnels = _rows(conn, "SELECT * FROM tunnels ORDER BY id")
        blocked = _rows(
            conn,
            "SELECT b.*, t.ip FROM blocked b "
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
    except sqlite3.OperationalError:
        return _EMPTY_STATE
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
    except sqlite3.OperationalError:
        return []
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
/* Access chain graph — Host Card Topology */
#graph-container { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; overflow: hidden; min-height: 200px; margin: 12px 0; position: relative;
  cursor: grab; }
#graph-container.fullscreen { position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  z-index: 100; margin: 0; border-radius: 0; border: none; min-height: unset; }
#graph-container.fullscreen svg { height: 100% !important; }
.graph-expand-btn { position: absolute; top: 6px; right: 6px; z-index: 6;
  background: var(--bg3); color: var(--dim); border: 1px solid var(--border);
  border-radius: 4px; padding: 3px 8px; font-family: inherit; font-size: 11px;
  cursor: pointer; }
.graph-expand-btn:hover { color: var(--accent); border-color: var(--accent); }
#graph-container.panning { cursor: grabbing; }
#graph-container svg { display: block; user-select: none; -webkit-user-select: none; }
.flow-node { cursor: default; }
.flow-action { rx: 8; ry: 8; stroke-width: 2; }
.flow-asset { rx: 14; ry: 14; stroke-width: 1.5; }
.flow-action-header { font-size: 10px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
.flow-node-title { font-size: 11px; font-weight: 600; }
.flow-node-detail { font-size: 10px; }
.flow-edge { fill: none; stroke-width: 2; marker-end: url(#flow-arrow); }
.flow-edge-active { stroke: #3fb950; }
.flow-edge-pending { stroke: #e3b341; stroke-dasharray: 6 3; }
.flow-edge-blocked { stroke: #f85149; stroke-dasharray: 6 3; }
.graph-legend { position: absolute; bottom: 6px; left: 6px; right: 6px;
  background: var(--bg2); border-top: 1px solid var(--border); padding: 4px 8px;
  font-size: 10px; color: var(--text); display: flex; gap: 8px; align-items: center;
  flex-wrap: wrap; z-index: 5; pointer-events: none; }
.graph-legend .legend-dim { color: var(--dim); font-weight: 600; }
.graph-legend .legend-item { display: inline-flex; align-items: center; gap: 4px; }
.tooltip { position: fixed; background: var(--bg3); border: 1px solid var(--border);
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
  <h2 onclick="toggleSection('graph')">Access Chain <button class="refresh-btn" onclick="event.stopPropagation(); refreshAll()">Refresh</button></h2>
  <div id="graph-body" class="section-body">
    <div id="graph-container"><button class="graph-expand-btn" onclick="toggleGraphFullscreen()" id="graph-expand-btn" title="Toggle fullscreen">&#x26F6;</button><svg id="graph"></svg><div class="graph-legend" id="graph-legend"></div><div class="tooltip" id="graph-tooltip"></div></div>
    <div class="tooltip" id="tooltip"></div>
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
  renderFlowGraph();
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
    cols: ['ip','os','role','ports','notes'],
    fmt: { ports: r => (r.ports||[]).map(p=>`${p.port}/${p.protocol} ${p.service}`).join(', ') }},
  { id: 'credentials', title: 'Credentials', key: 'credentials',
    cols: ['domain','username','secret_type','secret','cracked','source','tested'],
    fmt: { secret: r => r.secret || '',
           cracked: r => r.cracked ? 'yes' : '',
           tested: r => (r.tested_against||[]).map(t=>`${t.ip}/${t.service}:${t.works?'OK':'FAIL'}`).join(', ') }},
  { id: 'access', title: 'Access', key: 'access',
    cols: ['ip','username','access_type','privilege','method','active','session_ref'],
    fmt: { active: r => `<span class="status-${r.active?'active':'revoked'}">${r.active?'active':'revoked'}</span>` }},
  { id: 'vulns', title: 'Vulns', key: 'vulns',
    cols: ['title','severity','status','ip','vuln_type','details'],
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
    cols: ['technique','ip','reason','retry'],
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
      const orderedCols = { severity: {critical:0,high:1,medium:2,low:3,info:4},
        status: {exploited:0,found:1,blocked:2}, retry: {with_context:0,later:1,no:2} };
      rows = [...rows].sort((a,b) => {
        let va = getCellValue(a, col, def), vb = getCellValue(b, col, def);
        const ord = orderedCols[col];
        if (ord) { va = ord[va] ?? 99; vb = ord[vb] ?? 99; }
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

function toggleGraphFullscreen() {
  const c = document.getElementById('graph-container');
  const btn = document.getElementById('graph-expand-btn');
  c.classList.toggle('fullscreen');
  btn.textContent = c.classList.contains('fullscreen') ? '\u2716' : '\u26F6';
  // Reset persisted viewBox so graph re-fits to new container size
  _graphVB = null;
  requestAnimationFrame(() => requestAnimationFrame(() => renderFlowGraph()));
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const c = document.getElementById('graph-container');
    if (c && c.classList.contains('fullscreen')) { toggleGraphFullscreen(); }
  }
});

// --- Graph View Toggle ---

// --- Access Chain Graph (Flow View) ---
function renderFlowGraph() {
  const svg = document.getElementById('graph');
  const container = document.getElementById('graph-container');
  if (!state || (!state.access.length && !state.credentials.length && !state.vulns.length)) {
    svg.innerHTML = '<text x="50%" y="50" text-anchor="middle" fill="#8b949e" font-size="13">No chain data — provenance links (via_credential_id, via_access_id) needed</text>';
    svg.setAttribute('width', container.clientWidth);
    svg.setAttribute('height', 100);
    return;
  }

  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function escAttr(s) { return esc(s).replace(/"/g,'&quot;'); }
  function trunc(s, max) { s = String(s||''); return s.length > max ? s.slice(0, max-1)+'\u2026' : s; }

  // --- Build nodes ---
  const nodes = []; // { id, type, label, sublabel, detail, color, borderColor, chain_order, row }
  const nodeById = {};
  const edges = []; // { from, to, color }

  // Access → ACTION nodes
  for (const a of state.access) {
    if (a.in_graph === 0) continue;
    const host = a.ip || '';
    const techniqueLabel = a.technique_id ? `[${a.technique_id}] ` : '';
    const node = {
      id: `access:${a.id}`, type: 'action',
      label: `${techniqueLabel}${a.username} (${a.privilege})`,
      sublabel: trunc(a.method || a.access_type, 40),
      hostLabel: host,
      detail: `${a.username}@${host} [${a.access_type}, ${a.privilege}]\n${a.method}`,
      borderColor: a.active ? '#3fb950' : '#f85149',
      headerColor: '#1f6feb',
      headerText: a.access_type.toUpperCase(),
      chain_order: a.chain_order || 0,
    };
    nodes.push(node);
    nodeById[node.id] = node;
  }

  // Credentials → ASSET nodes
  for (const c of state.credentials) {
    if (c.in_graph === 0) continue;
    // Skip uncracked capture hashes (noisy)
    if (!c.cracked && ['net_ntlm','kerberos_tgs','dcc2','webapp_hash'].includes(c.secret_type)) continue;
    const label = c.domain ? `${c.domain}\\${c.username}` : c.username;
    const node = {
      id: `cred:${c.id}`, type: 'asset',
      label: label,
      sublabel: c.secret_type + (c.cracked ? ' (cracked)' : ''),
      hostLabel: '',
      detail: `${label} (${c.secret_type})\nsource: ${c.source}`,
      borderColor: '#8b949e',
      headerColor: '#30363d',
      headerText: 'CREDENTIAL',
      chain_order: c.chain_order || 0,
    };
    nodes.push(node);
    nodeById[node.id] = node;
  }

  // Vulns → ACTION (exploited) or ASSET (found, medium+)
  for (const v of state.vulns) {
    if (v.in_graph === 0) continue;
    if (v.severity === 'info') continue;
    const isAction = v.status === 'exploited';
    const techniqueLabel = v.technique_id ? `[${v.technique_id}] ` : '';
    const sevColors = { critical: '#f85149', high: '#d29922', medium: '#8b949e', low: '#8b949e' };
    const node = {
      id: `vuln:${v.id}`, type: isAction ? 'action' : 'asset',
      label: `${techniqueLabel}${trunc(v.title, 35)}`,
      sublabel: `${v.severity} | ${v.status}`,
      hostLabel: v.ip || '',
      detail: `${v.title}\n${v.severity} | ${v.status}${v.vuln_type ? '\ntype: ' + v.vuln_type : ''}${v.details ? '\n' + v.details : ''}`,
      borderColor: isAction ? '#3fb950' : (sevColors[v.severity] || '#8b949e'),
      headerColor: isAction ? '#238636' : '#d29922',
      headerText: isAction ? 'EXPLOITED' : v.severity.toUpperCase(),
      chain_order: v.chain_order || 0,
    };
    nodes.push(node);
    nodeById[node.id] = node;
  }

  // --- Build edges from provenance, synthesize action nodes for transitions ---
  let actionSeq = 0;

  // Helper: create a synthetic action node paired with its output asset
  // Action goes at the SAME column as the destination (ATT&CK Flow convention:
  // action and its produced asset appear at the same level)
  function insertAction(fromId, toId, actionLabel, color, srcCol, dstCol) {
    actionSeq++;
    const aid = `action:${actionSeq}`;
    const node = {
      id: aid, type: 'action',
      label: actionLabel, sublabel: '', hostLabel: '',
      detail: actionLabel,
      borderColor: color,
      headerColor: color === '#3fb950' ? '#238636' : color === '#58a6ff' ? '#1f6feb' : '#d29922',
      headerText: 'ACTION',
      chain_order: dstCol,  // same column as the asset it produces
    };
    nodes.push(node);
    nodeById[aid] = node;
    edges.push({ from: fromId, to: aid, color });
    edges.push({ from: aid, to: toId, color });
  }

  // credential → access (used cred to gain access) — access IS the action, direct edge
  for (const a of state.access) {
    if (a.in_graph === 0) continue;
    if (a.via_credential_id && nodeById[`cred:${a.via_credential_id}`]) {
      edges.push({ from: `cred:${a.via_credential_id}`, to: `access:${a.id}`, color: '#3fb950' });
    }
    if (a.via_access_id && nodeById[`access:${a.via_access_id}`]) {
      edges.push({ from: `access:${a.via_access_id}`, to: `access:${a.id}`, color: '#3fb950' });
    }
  }

  // access → credential (found cred during access) — INSERT action node
  for (const c of state.credentials) {
    if (c.in_graph === 0) continue;
    if (!nodeById[`cred:${c.id}`]) continue;
    if (c.via_access_id && nodeById[`access:${c.via_access_id}`]) {
      const src = (c.source || '').toLowerCase();
      let actionLabel = 'Credential Found';
      if (/spray|reuse/.test(src)) actionLabel = 'Password Spray';
      else if (/crack/.test(src)) actionLabel = 'Hash Recovery';
      else if (/runas|config|file|enum/.test(src)) actionLabel = 'Credential Discovery';
      else if (/dump|extract|secret/.test(src)) actionLabel = 'Credential Extraction';
      const srcNode = nodeById[`access:${c.via_access_id}`];
      const dstNode = nodeById[`cred:${c.id}`];
      insertAction(`access:${c.via_access_id}`, `cred:${c.id}`, actionLabel, '#58a6ff',
        srcNode.chain_order, dstNode.chain_order);
    }
    // vuln → credential — INSERT action node
    if (c.via_vuln_id && nodeById[`vuln:${c.via_vuln_id}`]) {
      const srcNode = nodeById[`vuln:${c.via_vuln_id}`];
      const dstNode = nodeById[`cred:${c.id}`];
      insertAction(`vuln:${c.via_vuln_id}`, `cred:${c.id}`, 'Hash Capture', '#58a6ff',
        srcNode.chain_order, dstNode.chain_order);
    }
  }

  // access → vuln (found/exploited vuln during access) — direct edge (vuln IS the finding)
  for (const v of state.vulns) {
    if (v.in_graph === 0) continue;
    if (v.severity === 'info') continue;
    if (v.via_access_id && nodeById[`access:${v.via_access_id}`] && nodeById[`vuln:${v.id}`]) {
      edges.push({ from: `access:${v.via_access_id}`, to: `vuln:${v.id}`, color: '#e3b341' });
    }
  }

  // --- Assign columns (left-to-right flow) ---
  // Use chain_order if set, else BFS depth from roots
  const hasOrder = nodes.some(n => n.chain_order > 0);
  if (hasOrder) {
    for (const n of nodes) {
      n.col = n.chain_order || 999;
    }
  } else {
    const incoming = new Set();
    for (const e of edges) incoming.add(e.to);
    const roots = nodes.filter(n => !incoming.has(n.id));
    const visited = new Set();
    const queue = roots.map(n => ({ id: n.id, depth: 0 }));
    for (const n of nodes) n.col = 999;
    while (queue.length) {
      const { id, depth } = queue.shift();
      if (visited.has(id)) continue;
      visited.add(id);
      if (nodeById[id]) nodeById[id].col = depth;
      for (const e of edges) {
        if (e.from === id && !visited.has(e.to)) {
          queue.push({ id: e.to, depth: depth + 1 });
        }
      }
    }
  }

  // --- Layout: left-to-right, parallel nodes stack vertically ---
  const NODE_W = 200;
  const NODE_H = 56;
  const H_GAP = 60;
  const V_GAP = 20;
  const PAD = 30;

  // Group nodes by column
  const colMap = {};
  for (const n of nodes) {
    if (!colMap[n.col]) colMap[n.col] = [];
    colMap[n.col].push(n);
  }
  const colKeys = Object.keys(colMap).map(Number).sort((a, b) => a - b);

  // Sort within each column: exploited vulns first, then actions, then access, then creds
  const typeSortOrder = { 'vuln': 0, 'action': 1, 'access': 2, 'asset': 3 };
  function nodeSort(a, b) {
    const aType = a.id.startsWith('vuln:') ? 'vuln' : a.id.startsWith('action:') ? 'action'
      : a.id.startsWith('access:') ? 'access' : 'asset';
    const bType = b.id.startsWith('vuln:') ? 'vuln' : b.id.startsWith('action:') ? 'action'
      : b.id.startsWith('access:') ? 'access' : 'asset';
    return (typeSortOrder[aType] || 9) - (typeSortOrder[bType] || 9);
  }
  for (const ck of colKeys) colMap[ck].sort(nodeSort);

  // Assign x, y positions — columns go left-to-right, nodes stack vertically
  let totalH = 0;
  let x = PAD;
  for (const ck of colKeys) {
    const colNodes = colMap[ck];
    const colH = colNodes.length * NODE_H + (colNodes.length - 1) * V_GAP;
    if (colH > totalH) totalH = colH;
    let y = PAD;
    for (const n of colNodes) {
      n.x = x;
      n.y = y;
      y += NODE_H + V_GAP;
    }
    x += NODE_W + H_GAP;
  }
  const totalW = x + PAD;
  totalH += PAD * 2;

  // Center each column vertically
  for (const ck of colKeys) {
    const colNodes = colMap[ck];
    const colH = colNodes.length * NODE_H + (colNodes.length - 1) * V_GAP;
    const offset = (totalH - colH) / 2 - PAD;
    for (const n of colNodes) n.y += offset;
  }

  // --- Render SVG ---
  let svgHtml = '<defs></defs>';

  // Draw edges — attach to closest edge of source/dest nodes
  for (const e of edges) {
    const src = nodeById[e.from];
    const dst = nodeById[e.to];
    if (!src || !dst) continue;

    // Node center points
    const scx = src.x + NODE_W / 2, scy = src.y + NODE_H / 2;
    const dcx = dst.x + NODE_W / 2, dcy = dst.y + NODE_H / 2;

    // Pick attachment points based on relative position
    let sx, sy, dx, dy, arrowPts;
    const sameCol = Math.abs(src.x - dst.x) < NODE_W / 2;
    const as = 6;

    if (sameCol) {
      // Vertical: connect bottom→top or top→bottom
      if (scy < dcy) {
        sx = scx; sy = src.y + NODE_H;  // bottom of src
        dx = dcx; dy = dst.y;            // top of dst
        arrowPts = `${dx},${dy} ${dx-as/2},${dy-as} ${dx+as/2},${dy-as}`;
      } else {
        sx = scx; sy = src.y;            // top of src
        dx = dcx; dy = dst.y + NODE_H;  // bottom of dst
        arrowPts = `${dx},${dy} ${dx-as/2},${dy+as} ${dx+as/2},${dy+as}`;
      }
      const my = sy + (dy - sy) * 0.5;
      var path = `M${sx},${sy} C${sx},${my} ${dx},${my} ${dx},${dy}`;
    } else if (scx < dcx) {
      // Left-to-right
      sx = src.x + NODE_W; sy = scy;    // right of src
      dx = dst.x;          dy = dcy;    // left of dst
      arrowPts = `${dx},${dy} ${dx-as},${dy-as/2} ${dx-as},${dy+as/2}`;
      const mx = sx + (dx - sx) * 0.5;
      var path = `M${sx},${sy} C${mx},${sy} ${mx},${dy} ${dx},${dy}`;
    } else {
      // Right-to-left (backward edge)
      sx = src.x;          sy = scy;    // left of src
      dx = dst.x + NODE_W; dy = dcy;    // right of dst
      arrowPts = `${dx},${dy} ${dx+as},${dy-as/2} ${dx+as},${dy+as/2}`;
      const mx = sx + (dx - sx) * 0.5;
      var path = `M${sx},${sy} C${mx},${sy} ${mx},${dy} ${dx},${dy}`;
    }

    const srcLabel = src.label || src.id;
    const dstLabel = dst.label || dst.id;
    const detailAttr = escAttr(`${srcLabel} \u2192 ${dstLabel}`);
    svgHtml += `<path class="flow-edge" d="${path}" stroke="${e.color}" data-detail="${detailAttr}" onmouseenter="showTip(event)" onmouseleave="hideTip()"/>`;
    svgHtml += `<polygon points="${arrowPts}" fill="${e.color}"/>`;
  }

  // Draw nodes
  for (const n of nodes) {
    svgHtml += `<g class="flow-node">`;
    // Background rect
    const bgFill = '#0d1117';
    svgHtml += `<rect class="${n.type === 'action' ? 'flow-action' : 'flow-asset'}" x="${n.x}" y="${n.y}" width="${NODE_W}" height="${NODE_H}" fill="${bgFill}" stroke="${n.borderColor}"/>`;
    // Header bar
    svgHtml += `<rect x="${n.x}" y="${n.y}" width="${NODE_W}" height="18" rx="${n.type === 'action' ? 8 : 14}" fill="${n.headerColor}"/>`;
    svgHtml += `<rect x="${n.x}" y="${n.y + 9}" width="${NODE_W}" height="9" fill="${n.headerColor}"/>`;
    // Header text
    svgHtml += `<text class="flow-action-header" x="${n.x + 8}" y="${n.y + 13}" fill="#fff">${esc(n.headerText)}${n.hostLabel ? '  ' + esc(n.hostLabel) : ''}</text>`;
    // Content via foreignObject
    const detailAttr = escAttr(n.detail);
    svgHtml += `<foreignObject x="${n.x + 6}" y="${n.y + 20}" width="${NODE_W - 12}" height="${NODE_H - 24}" data-detail="${detailAttr}" onmouseenter="showTip(event)" onmouseleave="hideTip()">`;
    svgHtml += `<div xmlns="http://www.w3.org/1999/xhtml" style="font-family:inherit;">`;
    svgHtml += `<div style="font-size:11px;font-weight:600;color:#c9d1d9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(n.label)}</div>`;
    svgHtml += `<div style="font-size:10px;color:#8b949e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(n.sublabel)}</div>`;
    svgHtml += `</div></foreignObject>`;
    svgHtml += `</g>`;
  }

  // Legend
  const legend = document.getElementById('graph-legend');
  legend.innerHTML = [
    '<span class="legend-dim">NODES</span>',
    '<span class="legend-item"><svg width="12" height="12"><rect width="12" height="12" rx="3" fill="none" stroke="#3fb950" stroke-width="2"/></svg>Access</span>',
    '<span class="legend-item"><svg width="12" height="12"><rect width="12" height="12" rx="3" fill="none" stroke="#1f6feb" stroke-width="2"/></svg>Action</span>',
    '<span class="legend-item"><svg width="12" height="12"><rect width="12" height="12" rx="6" fill="none" stroke="#8b949e" stroke-width="1.5"/></svg>Credential</span>',
    '<span class="legend-item"><svg width="12" height="12"><rect width="12" height="12" rx="3" fill="none" stroke="#238636" stroke-width="2"/></svg>Exploited vuln</span>',
  ].join('');

  svg.setAttribute('width', totalW);
  svg.setAttribute('height', totalH);
  svg.setAttribute('viewBox', `0 0 ${totalW} ${totalH}`);
  svg.innerHTML = svgHtml;

  _setupGraphZoomPan(svg, container, totalW, totalH);
}


// Zoom/pan state — kept outside renderFlowGraph so it survives re-renders
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
    if (ev.target.closest('.flow-node')) return;
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
  // Use graph-tooltip when inside fullscreen graph, else regular tooltip
  const inGraph = evt.currentTarget.closest('#graph-container');
  const tip = inGraph ? document.getElementById('graph-tooltip') : document.getElementById('tooltip');
  tip.textContent = detail;
  tip.style.display = 'block';
  // Position fixed relative to viewport — immune to container scroll/overflow
  let tx = evt.clientX + 12;
  let ty = evt.clientY + 12;
  const tipRect = tip.getBoundingClientRect();
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  if (tx + tipRect.width > vw - 8) tx = vw - tipRect.width - 8;
  if (ty + tipRect.height > vh - 8) ty = evt.clientY - tipRect.height - 8;
  if (ty < 4) ty = evt.clientY + 16;
  if (tx < 4) tx = 4;
  tip.style.left = tx + 'px';
  tip.style.top = ty + 'px';
}
function hideTip() {
  document.getElementById('tooltip').style.display = 'none';
  document.getElementById('graph-tooltip').style.display = 'none';
}

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

    ThreadingHTTPServer.allow_reuse_address = True
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
