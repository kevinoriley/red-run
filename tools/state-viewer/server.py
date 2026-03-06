#!/usr/bin/env python3
"""Read-only web dashboard for engagement state.

Single-file HTTP server serving an inline HTML/CSS/JS dashboard with live
updates via SSE.  No dependencies beyond Python stdlib.

Authentication:
    If ~/.config/red-run/viewer-token exists, the server binds to 0.0.0.0
    and requires the token to access any endpoint.  Without a token file,
    it binds to 127.0.0.1 only (no auth needed).

    Generate a token:  bash tools/state-viewer/generate-token.sh

Usage:
    python3 tools/state-viewer/server.py [--port 8099] [--db engagement/state.db]
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
/* Kill-chain graph */
#graph-container { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 6px; overflow: auto; min-height: 200px; margin: 12px 0; position: relative; }
#graph-container svg { display: block; }
.node rect, .node polygon, .node circle { stroke-width: 1.5; cursor: default; }
.node text { font-family: inherit; font-size: 11px; fill: var(--text); }
.edge { fill: none; stroke-width: 1.5; }
.edge-confirmed { stroke: var(--green); }
.edge-pending { stroke: var(--yellow); stroke-dasharray: 6 3; }
.edge-blocked { stroke: var(--red); stroke-dasharray: 3 3; }
marker polygon { stroke: none; }
.node-new { animation: fadeIn 0.5s ease-in; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
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
    <div id="graph-container"><svg id="graph"></svg></div>
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
  const sevCounts = {};
  state.vulns.forEach(v => { sevCounts[v.severity] = (sevCounts[v.severity]||0) + 1; });
  const sevStr = ['critical','high','medium','low','info']
    .filter(s => sevCounts[s]).map(s => `${sevCounts[s]} ${s}`).join(', ') || 'none';
  c.innerHTML = [
    card(state.targets.length, 'Targets'),
    card(state.credentials.length, 'Credentials'),
    card(state.access.filter(a=>a.active).length, 'Active Access'),
    card(state.vulns.length, 'Vulns', sevStr),
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
    fmt: { secret: r => r.secret ? (r.secret.length > 24 ? r.secret.slice(0,24)+'...' : r.secret) : '',
           cracked: r => r.cracked ? 'yes' : '',
           tested: r => (r.tested_against||[]).map(t=>`${t.host}/${t.service}:${t.works?'OK':'FAIL'}`).join(', ') }},
  { id: 'access', title: 'Access', key: 'access',
    cols: ['host','username','access_type','privilege','method','active','session_ref'],
    fmt: { active: r => `<span class="status-${r.active?'active':'revoked'}">${r.active?'active':'revoked'}</span>` }},
  { id: 'vulns', title: 'Vulns', key: 'vulns',
    cols: ['title','severity','status','host','endpoint','vuln_type','details'],
    fmt: { severity: r => `<span class="badge sev-${r.severity}">${r.severity}</span>`,
           details: r => r.details ? (r.details.length > 60 ? r.details.slice(0,60)+'...' : r.details) : '' }},
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
        const plain = String(val).replace(/<[^>]*>/g, '');
        html += `<td title="${plain.replace(/"/g,'&quot;')}"><div class="cell">${val}</div></td>`;
      }
      html += '</tr>';
    }
    if (!rows.length) html += `<tr><td colspan="${def.cols.length}" style="color:var(--dim);text-align:center">No data</td></tr>`;
    html += '</tbody></table></div></div>';
  }
  container.innerHTML = html;
}

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

// --- Kill-Chain Graph ---
function renderGraph() {
  const svg = document.getElementById('graph');
  const container = document.getElementById('graph-container');
  if (!state || (!state.targets.length && !state.vulns.length)) {
    svg.innerHTML = '<text x="50%" y="50" text-anchor="middle" fill="#8b949e" font-size="13">No data for graph</text>';
    svg.setAttribute('width', container.clientWidth);
    svg.setAttribute('height', 100);
    return;
  }

  // Build nodes and edges
  const nodes = []; // { id, type, label, sub, detail, layer }
  const edges = []; // { from, to, style }
  const nodeMap = {};

  function addNode(id, type, label, sub, detail) {
    if (nodeMap[id]) return;
    nodeMap[id] = { id, type, label, sub: sub||'', detail: detail||'', layer: 0 };
    nodes.push(nodeMap[id]);
  }

  // Build a hostname lookup: IP -> role/notes for subtitle
  const hostInfo = {};
  for (const t of state.targets) {
    const parts = [];
    if (t.role) parts.push(t.role);
    else if (t.os) parts.push(t.os);
    hostInfo[t.host] = parts.join(' ');
  }

  // Root attacker node
  addNode('attacker', 'attacker', 'Attacker', '', '');
  nodeMap['attacker'].layer = 0;

  // Targets (hosts)
  const pivotDestHosts = new Set(); // populated during pivot edge rendering
  for (const t of state.targets) {
    const ports = (t.ports||[]).map(p=>`${p.port}/${p.service||p.protocol}`).join(', ');
    const sub = t.role || t.os || '';
    addNode(`host:${t.host}`, 'host', t.host, sub, `${t.os} ${t.role}\n${ports}`.trim());
  }

  // Pre-create access nodes so via_access_id references resolve during vuln/cred processing
  for (const a of state.access) {
    const label = `${a.username}@${a.host}`;
    const sub = `${a.access_type} | ${a.privilege}`;
    addNode(`access:${a.id}`, 'access', label, sub, `${a.access_type} | ${a.privilege}\n${a.method}`);
  }

  // Vulns — use via_access_id for provenance, fall back to host link
  const sevColors = { critical:'#f85149', high:'#d29922', medium:'#e3b341', low:'#58a6ff', info:'#8b949e' };
  for (const v of state.vulns) {
    const host = v.host || 'unknown';
    addNode(`vuln:${v.id}`, 'vuln', v.title, '', `${v.severity} | ${v.status}\n${v.endpoint}\n${v.details||''}`.trim());
    nodeMap[`vuln:${v.id}`].severity = v.severity;
    // Explicit provenance: via_access_id links vuln to the access that discovered it
    if (v.via_access_id && nodeMap[`access:${v.via_access_id}`]) {
      edges.push({ from: `access:${v.via_access_id}`, to: `vuln:${v.id}`, style: 'pending' });
    } else if (nodeMap[`host:${host}`]) {
      edges.push({ from: `host:${host}`, to: `vuln:${v.id}`, style: 'pending' });
    }
  }

  // Credentials — use via_access_id for explicit provenance, heuristics as fallback
  const providedPattern = /\b(provided|scope|pre-engagement|given|initial|pentest)\b/i;
  const providedCredIds = new Set(); // cred IDs that are pre-provided
  for (const c of state.credentials) {
    const label = c.domain ? `${c.domain}\\${c.username}` : c.username;
    const sub = c.secret_type + (c.cracked ? ' (cracked)' : '');
    addNode(`cred:${c.id}`, 'cred', label, sub, `${c.secret_type}${c.cracked?' (cracked)':''}\nsource: ${c.source}`);
    if (c.source && providedPattern.test(c.source)) {
      edges.push({ from: 'attacker', to: `cred:${c.id}`, style: 'confirmed' });
      providedCredIds.add(c.id);
      continue;
    }
    // Explicit provenance: via_access_id links cred to the access that discovered it
    if (c.via_access_id && nodeMap[`access:${c.via_access_id}`]) {
      edges.push({ from: `access:${c.via_access_id}`, to: `cred:${c.id}`, style: 'confirmed' });
      continue;
    }
    // Heuristic fallback: match source text to vuln types/titles
    let linked = false;
    for (const v of state.vulns) {
      if (c.source && (c.source.toLowerCase().includes(v.vuln_type.toLowerCase()) ||
          c.source.toLowerCase().includes(v.title.toLowerCase().slice(0,20)))) {
        edges.push({ from: `vuln:${v.id}`, to: `cred:${c.id}`, style: 'confirmed' });
        linked = true; break;
      }
    }
    if (!linked) {
      for (const ta of (c.tested_against||[])) {
        if (ta.works && nodeMap[`host:${ta.host}`]) {
          edges.push({ from: `host:${ta.host}`, to: `cred:${c.id}`, style: 'confirmed' });
          linked = true; break;
        }
      }
    }
  }

  // Access edges (nodes already created above)
  const hostsViaProvidedCred = new Set(); // hosts reached via provided creds
  for (const a of state.access) {
    let linked = false;
    for (const c of state.credentials) {
      const cLabel = c.domain ? `${c.domain}\\${c.username}` : c.username;
      if (a.username && (a.username === c.username || a.username === cLabel ||
          a.method && a.method.toLowerCase().includes(c.username.toLowerCase()))) {
        edges.push({ from: `cred:${c.id}`, to: `access:${a.id}`, style: a.active ? 'confirmed' : 'blocked' });
        linked = true;
        // Track provided-cred chain: access -> host bridge needed
        if (providedCredIds.has(c.id)) {
          hostsViaProvidedCred.add(a.host);
          if (nodeMap[`host:${a.host}`]) {
            edges.push({ from: `access:${a.id}`, to: `host:${a.host}`, style: 'confirmed' });
          }
        }
        break;
      }
    }
    if (!linked && nodeMap[`host:${a.host}`]) {
      let vlinked = false;
      for (const v of state.vulns) {
        if (v.host === a.host && a.method && a.method.toLowerCase().includes(v.vuln_type.toLowerCase().slice(0,8))) {
          edges.push({ from: `vuln:${v.id}`, to: `access:${a.id}`, style: a.active ? 'confirmed' : 'blocked' });
          vlinked = true; break;
        }
      }
      if (!vlinked) {
        edges.push({ from: `host:${a.host}`, to: `access:${a.id}`, style: a.active ? 'confirmed' : 'blocked' });
      }
    }
  }

  // Pivots — rendered as labeled edges, not nodes
  const pivotStyles = { exploited: 'confirmed', identified: 'pending', blocked: 'blocked' };
  const targetHosts = state.targets.map(t => t.host);
  for (const p of state.pivot_map) {
    const style = pivotStyles[p.status] || 'pending';
    const methodShort = (p.method || 'pivot').split(/[.\-,]/)[0].trim().slice(0, 40);
    const label = methodShort + (p.status !== 'exploited' ? ` (${p.status})` : '');
    // Find best source: active access on source host, or the host itself
    // Source text may be descriptive (e.g. "DC01.pirate.htb (10.129.244.95) - gMSA...")
    let fromId = null;
    for (const a of state.access) {
      if (a.active && (a.host === p.source || p.source.includes(a.host))) {
        fromId = `access:${a.id}`; break;
      }
    }
    if (!fromId) {
      if (nodeMap[`host:${p.source}`]) fromId = `host:${p.source}`;
      else {
        for (const h of targetHosts) {
          if (p.source.includes(h) && nodeMap[`host:${h}`]) { fromId = `host:${h}`; break; }
        }
      }
    }
    // Match destination to a target host (exact match, IP substring, or subnet prefix)
    let destHost = null;
    if (nodeMap[`host:${p.destination}`]) {
      destHost = p.destination;
    } else {
      for (const h of targetHosts) {
        if (p.destination.includes(h)) { destHost = h; break; }
        // Match subnet references (e.g. "192.168.100.0/24" matches host "192.168.100.2")
        const prefix = h.split('.').slice(0,3).join('.');
        if (p.destination.includes(prefix + '.')) { destHost = h; break; }
      }
    }
    const toId = destHost ? `host:${destHost}` : null;
    if (fromId && toId) {
      edges.push({ from: fromId, to: toId, style, label });
      pivotDestHosts.add(destHost);
    }
  }

  // Blocked — tables only, not in graph

  // Connect attacker to initial targets (no inbound pivots)
  // Skip hosts already reachable via provided-cred chain
  for (const t of state.targets) {
    if (!pivotDestHosts.has(t.host) && !hostsViaProvidedCred.has(t.host)) {
      edges.push({ from: 'attacker', to: `host:${t.host}`, style: 'confirmed' });
    }
  }

  // Prune dead-end vulns: remove vuln nodes that have no outbound edges
  // (they didn't lead to creds, access, or anything else — keep them in tables only)
  const vulnOutbound = new Set();
  for (const e of edges) {
    if (e.from.startsWith('vuln:')) vulnOutbound.add(e.from);
  }
  const deadVulns = new Set();
  for (const n of nodes) {
    if (n.type === 'vuln' && !vulnOutbound.has(n.id)) deadVulns.add(n.id);
  }
  if (deadVulns.size) {
    // Remove dead vuln nodes and their inbound edges
    for (let i = nodes.length - 1; i >= 0; i--) {
      if (deadVulns.has(nodes[i].id)) { delete nodeMap[nodes[i].id]; nodes.splice(i, 1); }
    }
    for (let i = edges.length - 1; i >= 0; i--) {
      if (deadVulns.has(edges[i].to)) edges.splice(i, 1);
    }
  }

  // --- Layered layout ---
  // BFS from attacker to assign layers
  const adj = {};
  for (const n of nodes) adj[n.id] = [];
  for (const e of edges) {
    if (adj[e.from]) adj[e.from].push(e.to);
  }
  const visited = new Set(['attacker']);
  let queue = ['attacker'];
  nodeMap['attacker'].layer = 0;
  while (queue.length) {
    const next = [];
    for (const nid of queue) {
      for (const child of (adj[nid]||[])) {
        if (!visited.has(child) && nodeMap[child]) {
          nodeMap[child].layer = nodeMap[nid].layer + 1;
          visited.add(child);
          next.push(child);
        }
      }
    }
    queue = next;
  }
  // Unvisited nodes get layer based on type
  for (const n of nodes) {
    if (!visited.has(n.id)) {
      n.layer = { host: 1, vuln: 2, cred: 3, access: 4 }[n.type] || 1;
    }
  }

  // Group by layer
  const layers = {};
  for (const n of nodes) {
    if (!layers[n.layer]) layers[n.layer] = [];
    layers[n.layer].push(n);
  }
  const maxLayer = Math.max(...Object.keys(layers).map(Number));

  const nodeW = 180, nodeH = 44, layerGap = 230, rowGap = 60, padX = 60, padY = 40;
  const positions = {};

  // Build reverse adjacency for barycenter ordering
  const radj = {};
  for (const n of nodes) radj[n.id] = [];
  for (const e of edges) {
    if (radj[e.to]) radj[e.to].push(e.from);
  }

  // First pass: assign initial positions
  for (let l = 0; l <= maxLayer; l++) {
    const group = layers[l] || [];
    const x = padX + l * layerGap;
    const totalH = group.length * rowGap;
    const startY = padY + Math.max(0, (300 - totalH) / 2);
    group.forEach((n, i) => {
      positions[n.id] = { x, y: startY + i * rowGap, w: nodeW, h: nodeH };
    });
  }

  // Barycenter ordering: sort nodes in each layer by average Y of neighbors
  // in previous layer to reduce edge crossings. Run 3 passes.
  for (let pass = 0; pass < 3; pass++) {
    for (let l = 1; l <= maxLayer; l++) {
      const group = layers[l] || [];
      group.forEach(n => {
        const parents = (radj[n.id] || []).filter(pid => positions[pid]);
        if (parents.length) {
          n._bary = parents.reduce((s, pid) => s + positions[pid].y, 0) / parents.length;
        } else {
          n._bary = positions[n.id].y;
        }
      });
      group.sort((a, b) => a._bary - b._bary);
      const x = padX + l * layerGap;
      const totalH = group.length * rowGap;
      const startY = padY + Math.max(0, (300 - totalH) / 2);
      group.forEach((n, i) => {
        positions[n.id].y = startY + i * rowGap;
      });
    }
  }

  const svgW = padX * 2 + (maxLayer + 1) * layerGap;
  const maxY = Math.max(...Object.values(positions).map(p => p.y + p.h)) + padY;
  const svgH = Math.max(200, maxY);

  // Render SVG
  let svgHtml = `<defs>
    <marker id="ah-green" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#3fb950"/></marker>
    <marker id="ah-yellow" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#e3b341"/></marker>
    <marker id="ah-red" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#f85149"/></marker>
  </defs>`;

  // Draw edges
  const edgeColors = { confirmed: '#3fb950', pending: '#e3b341', blocked: '#f85149' };
  for (const e of edges) {
    const from = positions[e.from], to = positions[e.to];
    if (!from || !to) continue;
    const x1 = from.x + from.w, y1 = from.y + from.h/2;
    const x2 = to.x, y2 = to.y + to.h/2;
    const mx = (x1 + x2) / 2;
    const cls = `edge edge-${e.style}`;
    const marker = { confirmed: 'ah-green', pending: 'ah-yellow', blocked: 'ah-red' }[e.style] || 'ah-green';
    svgHtml += `<path class="${cls}" d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" marker-end="url(#${marker})"/>`;
    if (e.label) {
      const lx = mx, ly = (y1 + y2) / 2 - 4;
      const col = edgeColors[e.style] || '#8b949e';
      svgHtml += `<rect x="${lx - e.label.length*3.2 - 4}" y="${ly - 9}" width="${e.label.length*6.4 + 8}" height="14" rx="3" fill="#0d1117" fill-opacity="0.85"/>`;
      svgHtml += `<text x="${lx}" y="${ly}" text-anchor="middle" font-size="9" fill="${col}" font-weight="600">${esc(e.label)}</text>`;
    }
  }

  // Draw nodes
  const colors = {
    attacker: { fill: '#21262d', stroke: '#f85149' },
    host: { fill: '#0d2240', stroke: '#58a6ff' },
    vuln: { fill: '#3d1f00', stroke: '#d29922' },
    cred: { fill: '#1f0d3d', stroke: '#bc8cff' },
    access: { fill: '#0d3d0d', stroke: '#3fb950' },
  };

  function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;'); }
  function escAttr(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;'); }
  function trunc(s, max) { return s.length > max ? s.slice(0, max-2)+'..' : s; }

  for (const n of nodes) {
    const p = positions[n.id];
    if (!p) continue;
    const c = colors[n.type] || colors.host;
    const label = esc(trunc(n.label, 26));
    const sub = n.sub ? esc(trunc(n.sub, 30)) : '';
    const detailEsc = escAttr(n.detail);
    const hasSub = !!sub;
    // Text Y positions: single line centered, two lines offset
    const labelY = hasSub ? p.y + p.h/2 - 2 : p.y + p.h/2 + 4;
    const subY = p.y + p.h/2 + 10;

    // Severity-aware stroke for vulns
    let stroke = c.stroke;
    if (n.type === 'vuln' && n.severity && sevColors[n.severity]) {
      stroke = sevColors[n.severity];
    }
    // Sub-label color
    let subColor = '#8b949e';
    if (n.type === 'vuln' && n.severity && sevColors[n.severity]) {
      subColor = sevColors[n.severity];
    }

    let shape;
    if (n.type === 'vuln') {
      const cx = p.x + p.w/2, cy = p.y + p.h/2, rx = p.w/2, ry = p.h/2;
      shape = `<polygon points="${cx},${cy-ry} ${cx+rx},${cy} ${cx},${cy+ry} ${cx-rx},${cy}" fill="${c.fill}" stroke="${stroke}"/>`;
    } else if (n.type === 'access') {
      shape = `<rect x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="4" fill="${c.fill}" stroke="${stroke}"/>`;
      shape += `<rect x="${p.x+3}" y="${p.y+3}" width="${p.w-6}" height="${p.h-6}" rx="2" fill="none" stroke="${stroke}" stroke-width="0.5"/>`;
    } else if (n.type === 'cred') {
      const x=p.x, y=p.y, w=p.w, h=p.h, inset=14;
      shape = `<polygon points="${x+inset},${y} ${x+w-inset},${y} ${x+w},${y+h/2} ${x+w-inset},${y+h} ${x+inset},${y+h} ${x},${y+h/2}" fill="${c.fill}" stroke="${stroke}"/>`;
    } else {
      shape = `<rect x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="6" fill="${c.fill}" stroke="${stroke}"/>`;
    }

    svgHtml += `<g class="node node-new" data-detail="${detailEsc}" onmouseenter="showTip(evt)" onmouseleave="hideTip()">`;
    svgHtml += shape;
    svgHtml += `<text x="${p.x + p.w/2}" y="${labelY}" text-anchor="middle">${label}</text>`;
    if (hasSub) {
      svgHtml += `<text x="${p.x + p.w/2}" y="${subY}" text-anchor="middle" font-size="9" fill="${subColor}">${sub}</text>`;
    }
    svgHtml += `</g>`;
  }

  // --- Legend ---
  const legendY = svgH;
  const legendItems = [
    { shape: 'rect', fill: '#0d2240', stroke: '#58a6ff', label: 'Host' },
    { shape: 'diamond', fill: '#3d1f00', stroke: '#d29922', label: 'Vuln' },
    { shape: 'hex', fill: '#1f0d3d', stroke: '#bc8cff', label: 'Credential' },
    { shape: 'dblrect', fill: '#0d3d0d', stroke: '#3fb950', label: 'Access' },
  ];
  const edgeLegend = [
    { cls: 'edge-confirmed', label: 'Exploited' },
    { cls: 'edge-pending', label: 'Identified' },
    { cls: 'edge-blocked', label: 'Blocked' },
  ];
  const legendH = 36;
  let lx = padX;
  svgHtml += `<g class="legend">`;
  svgHtml += `<text x="${lx}" y="${legendY + 14}" font-size="10" fill="#8b949e" font-weight="600">LEGEND</text>`;
  lx += 58;
  for (const item of legendItems) {
    const iy = legendY + 4, iw = 16, ih = 14;
    if (item.shape === 'diamond') {
      const cx = lx+iw/2, cy = iy+ih/2;
      svgHtml += `<polygon points="${cx},${iy} ${lx+iw},${cy} ${cx},${iy+ih} ${lx},${cy}" fill="${item.fill}" stroke="${item.stroke}" stroke-width="1.5"/>`;
    } else if (item.shape === 'hex') {
      const ins = 4;
      svgHtml += `<polygon points="${lx+ins},${iy} ${lx+iw-ins},${iy} ${lx+iw},${iy+ih/2} ${lx+iw-ins},${iy+ih} ${lx+ins},${iy+ih} ${lx},${iy+ih/2}" fill="${item.fill}" stroke="${item.stroke}" stroke-width="1.5"/>`;
    } else if (item.shape === 'dblrect') {
      svgHtml += `<rect x="${lx}" y="${iy}" width="${iw}" height="${ih}" rx="2" fill="${item.fill}" stroke="${item.stroke}" stroke-width="1.5"/>`;
      svgHtml += `<rect x="${lx+2}" y="${iy+2}" width="${iw-4}" height="${ih-4}" rx="1" fill="none" stroke="${item.stroke}" stroke-width="0.5"/>`;
    } else {
      svgHtml += `<rect x="${lx}" y="${iy}" width="${iw}" height="${ih}" rx="3" fill="${item.fill}" stroke="${item.stroke}" stroke-width="1.5"/>`;
    }
    svgHtml += `<text x="${lx+iw+5}" y="${iy+ih-2}" font-size="10" fill="#c9d1d9">${item.label}</text>`;
    lx += iw + 8 + item.label.length * 6.5 + 12;
  }
  // Edge legend
  lx += 8;
  for (const item of edgeLegend) {
    const iy = legendY + 11;
    svgHtml += `<line x1="${lx}" y1="${iy}" x2="${lx+20}" y2="${iy}" class="edge ${item.cls}" stroke-width="2"/>`;
    svgHtml += `<text x="${lx+25}" y="${iy+4}" font-size="10" fill="#c9d1d9">${item.label}</text>`;
    lx += 30 + item.label.length * 6.5 + 10;
  }
  svgHtml += `</g>`;

  svg.setAttribute('width', Math.max(svgW, lx + padX));
  svg.setAttribute('height', svgH + legendH);
  svg.innerHTML = svgHtml;
}

function showTip(evt) {
  const detail = evt.currentTarget.dataset.detail;
  if (!detail) return;
  const tip = document.getElementById('tooltip');
  tip.textContent = detail;
  tip.style.display = 'block';
  const rect = document.getElementById('graph-container').getBoundingClientRect();
  tip.style.left = (evt.clientX - rect.left + 12) + 'px';
  tip.style.top = (evt.clientY - rect.top + 12) + 'px';
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
                        self.wfile.write(f"data: {json.dumps({'type': 'state', 'payload': data}, default=str)}\n\n".encode())
                        self.wfile.flush()
                        last_full = now
                        if data["events"]:
                            last_event_id = max(e["id"] for e in data["events"])
                    else:
                        events = _get_events_since(self.db_path, last_event_id)
                        if events:
                            last_event_id = max(e["id"] for e in events)
                            self.wfile.write(f"data: {json.dumps({'type': 'events', 'payload': events}, default=str)}\n\n".encode())
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
    parser.add_argument("--port", type=int, default=8099, help="Listen port (default: 8099)")
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
    print(f"state-viewer: http://{bind_addr}:{args.port}")
    if bind_addr == "0.0.0.0":
        for ip in _get_local_ips():
            print(f"  remote:     http://{ip}:{args.port}")
        print(f"\nIf your VM uses NAT, access via http://localhost:{args.port} on the host")
        print(f"after adding a port forwarding rule (host {args.port} -> guest {args.port}).")
    print(f"database: {db_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
