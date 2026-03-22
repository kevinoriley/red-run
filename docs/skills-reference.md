# Skills Reference

red-run includes 67 skills across 7 categories. Each skill is a self-contained `SKILL.md` file under `skills/`.

## Skill Types

### Orchestrator

The **orchestrator** (`skills/orchestrator/SKILL.md`) takes a target, runs reconnaissance, routes to discovery skills, and chains vulnerabilities via state management. It's the entry point for all multi-phase penetration tests. See [Running an Engagement](running-an-engagement.md) for the full workflow.

### Discovery Skills

**Discovery skills** enumerate attack surface and identify vulnerabilities. Their decision trees recommend technique skills, but the agent returns these recommendations to the orchestrator — it never invokes the next skill itself. There are 4 discovery skills:

- `web-discovery` — web application enumeration and vulnerability identification
- `ad-discovery` — Active Directory enumeration and attack surface mapping
- `linux-discovery` — Linux host enumeration and privilege escalation assessment
- `windows-discovery` — Windows host enumeration and privilege escalation assessment

Discovery skills run in agents with **state** access, allowing them to write findings mid-run.

### Technique Skills

**Technique skills** exploit specific vulnerability classes. Each covers one technique thoroughly — assessment, confirmation, exploitation, and escalation/pivot routing. There are 62 technique skills across all categories.

Technique skills run in agents with **state** access. They write critical discoveries (captured hashes, credentials, confirmed vulns) mid-run and report all findings in their return summary.

## OPSEC Ratings

Every skill declares an OPSEC rating in its frontmatter:

| Rating | Meaning | Examples |
|--------|---------|----------|
| **low** | Passive or read-only operations | Web discovery, AD enumeration via LDAP |
| **medium** | Creates artifacts on target | File uploads, credential testing, tool execution |
| **high** | Noisy, likely detected by EDR/SOC | Kernel exploits, credential dumping, AV evasion |

OPSEC ratings are included in skill-router search results so the orchestrator can factor detection risk into routing decisions.

## Skill Inventory

### Web Application (33 skills)

| Skill | Technique | OPSEC |
|-------|-----------|-------|
| `web-discovery` | Content discovery, parameter fuzzing, vulnerability routing | low |
| `sql-injection-union` | UNION-based extraction (MySQL, MSSQL, Postgres, Oracle, SQLite) | medium |
| `sql-injection-error` | Error-based extraction (EXTRACTVALUE, CONVERT, CAST) | medium |
| `sql-injection-blind` | Boolean, time-based, OOB blind extraction | medium |
| `sql-injection-stacked` | Stacked queries, second-order injection, command execution | high |
| `xss-reflected` | Reflected XSS, filter/WAF/CSP bypass, impact demonstration | low |
| `xss-stored` | Stored + blind XSS, callback setup, self-XSS escalation | medium |
| `xss-dom` | DOM-based XSS, sources/sinks, postMessage, DOM clobbering | low |
| `ssti-jinja2` | Jinja2/Python SSTI (+ Mako, Tornado, Django) | medium |
| `ssti-twig` | Twig/PHP SSTI (+ Smarty, Blade, Latte) | medium |
| `ssti-freemarker` | Freemarker/Java SSTI (+ Velocity, SpEL, Thymeleaf, Pebble, Groovy) | medium |
| `ssrf` | Basic/blind SSRF, cloud metadata, filter bypass, gopher/dict protocol | medium |
| `lfi` | LFI, PHP wrappers, 8 LFI-to-RCE methods, filter bypass, RFI | medium |
| `command-injection` | OS command injection, filter bypass, blind techniques, argument injection | high |
| `python-code-injection` | Python eval()/exec()/compile() injection, sandbox escape | high |
| `xxe` | Classic/blind/OOB XXE, error-based, XInclude, file format injection | medium |
| `file-upload-bypass` | Extension/content-type/magic byte bypass, config exploitation, polyglots | medium |
| `deserialization-java` | ysoserial gadget chains, JNDI/Log4Shell, JSF ViewState | high |
| `deserialization-php` | Magic methods, POP chains, PHPGGC, phar:// polyglots | high |
| `deserialization-dotnet` | ysoserial.net, ViewState/machine keys, JSON.NET TypeNameHandling | high |
| `jwt-attacks` | alg:none, key confusion, kid injection, jwk/jku spoofing | medium |
| `request-smuggling` | CL.TE, TE.CL, TE.TE, H2 downgrade, h2c smuggling, response desync | medium |
| `nosql-injection` | MongoDB operator injection, auth bypass, blind regex extraction | medium |
| `ldap-injection` | LDAP filter injection, wildcard auth bypass, blind attribute extraction | medium |
| `idor` | Horizontal/vertical access control bypass, UUID prediction, API IDOR | low |
| `cors-misconfiguration` | Origin reflection, null origin, regex bypass, subdomain trust | low |
| `csrf` | Token bypass, SameSite bypass, JSON CSRF, file upload CSRF | medium |
| `oauth-attacks` | Redirect URI bypass, state bypass, code theft, token leakage | medium |
| `password-reset-poisoning` | Host header poisoning, Referer token leakage, email injection | medium |
| `2fa-bypass` | Response manipulation, direct navigation, OTP brute-force, session attacks | medium |
| `race-condition` | Limit-overrun, HTTP/2 single-packet, last-byte sync, TOCTOU | medium |
| `ajp-ghostcat` | AJP Ghostcat (CVE-2020-1938) file read, JSP inclusion RCE | high |
| `tomcat-manager-deploy` | WAR deployment RCE via Tomcat manager API | high |

### Active Directory (16 skills)

All AD skills follow a **Kerberos-first authentication** convention — commands default to ccache-based Kerberos auth (`-k -no-pass`, `--use-kcache`, `-k`) to avoid NTLM detection signatures (Event 4776, CrowdStrike Identity Module PTH signatures).

| Skill | Technique | OPSEC |
|-------|-----------|-------|
| `ad-discovery` | Domain enumeration (BloodHound, LDAP, NetExec), attack surface mapping | low |
| `kerberos-roasting` | Kerberoasting + AS-REP Roasting + Timeroasting | medium |
| `password-spraying` | Lockout-safe domain spray (Kerberos/NTLM/OWA) | medium |
| `pass-the-hash` | PTH, Over-Pass-the-Hash, Pass-the-Key, Pass-the-Ticket | medium |
| `kerberos-delegation` | Unconstrained, Constrained (S4U), RBCD | medium |
| `kerberos-ticket-forging` | Golden, Silver, Diamond, Sapphire tickets | high |
| `acl-abuse` | GenericAll/Write, WriteDACL, WriteOwner, shadow credentials | medium |
| `adcs-template-abuse` | ESC1/2/3/6 — SAN manipulation, any-purpose EKU | medium |
| `adcs-access-and-relay` | ESC4/5/7/8/11 — template/CA ACL abuse, NTLM relay | high |
| `adcs-persistence` | ESC9-15, Golden Certificate, certificate theft | high |
| `auth-coercion-relay` | PetitPotam/PrinterBug/DFSCoerce, NTLM relay, LLMNR poisoning | high |
| `credential-dumping` | DCSync, NTDS, SAM, LAPS, gMSA, dMSA BadSuccessor, DSRM | high |
| `gpo-abuse` | GPO exploitation, SYSVOL script poisoning, GPP passwords | medium |
| `trust-attacks` | SID history injection, inter-realm TGT forging, PAM trust | high |
| `sccm-exploitation` | SCCM enumeration, NAA creds, PXE boot, app deployment | high |
| `ad-persistence` | DCShadow, Skeleton Key, custom SSP, Golden SAML | high |

> **Kerberos-first exception:** Relay/coercion attacks (`auth-coercion-relay`) are inherently NTLM/network-level. The skill documents why Kerberos auth doesn't apply and notes the NTLM detection surface.

### Privilege Escalation (11 skills)

| Skill | Technique | OPSEC |
|-------|-----------|-------|
| `linux-discovery` | LinPEAS/LinEnum/pspy enumeration, sudo/SUID/capabilities assessment | low |
| `linux-sudo-suid-capabilities` | Sudo NOPASSWD/CVE-2021-3156, SUID GTFOBins, 20+ capabilities | medium |
| `linux-cron-service-abuse` | Cron script hijack, wildcard injection, systemd abuse, PwnKit | medium |
| `linux-file-path-abuse` | Writable /etc/passwd, NFS no_root_squash, Docker group escape | medium |
| `linux-kernel-exploits` | DirtyPipe/DirtyCow/GameOver(lay)/10+ CVEs, container kernel escape | high |
| `windows-discovery` | WinPEAS/PowerUp/Seatbelt/Watson enumeration, privilege checks | low |
| `windows-token-impersonation` | Potato family, SeDebug/SeBackup/SeRestore exploitation | medium |
| `windows-service-dll-abuse` | Unquoted paths, weak perms, DLL hijacking, COM hijacking | medium |
| `windows-uac-bypass` | Fodhelper/eventvwr/CMSTP/WSReset, AlwaysInstallElevated MSI | medium |
| `windows-credential-harvesting` | HiveNightmare, DPAPI, browser creds, PS history, cloud creds | medium |
| `windows-kernel-exploits` | PrintNightmare/EternalBlue/MS16-032, BYOVD, named pipes | high |

### Infrastructure (4 skills)

| Skill | Technique | OPSEC |
|-------|-----------|-------|
| `network-recon` | Passive recon, host discovery, nmap, 20+ protocol enumerations | low |
| `pivoting-tunneling` | SSH tunneling, Ligolo-ng, Chisel, socat, DNS/ICMP tunneling | medium |
| `container-escapes` | Docker socket/privileged/cgroup escape, K8s exploitation | high |
| `smb-exploitation` | MS08-067, MS17-010/EternalBlue, SMBGhost | high |

### Evasion (1 skill)

| Skill | Technique | OPSEC |
|-------|-----------|-------|
| `av-edr-evasion` | Custom payload compilation, AMSI bypass, ETW patching, LOLBins | high |

### Utility (2 skills)

| Skill | Purpose |
|-------|---------|
| `orchestrator` | Entry point — recon, routing, chaining, state management |
| `retrospective` | Post-engagement lessons-learned analysis |

## Inter-Skill Routing

Skills reference each other using **bold skill names** in their escalation sections. When a skill says:

> Route to **kerberos-roasting**. Pass: domain, DC IP, user list.

The orchestrator looks up `kerberos-roasting` in the routing table, spawns the `ad-exploit-agent`, and passes the context.

**Key routing rules:**

- The orchestrator makes every routing decision — agents never load other skills
- Context (injection point, target technology, working payloads) is passed in the task prompt
- Discovery skills recommend technique skills; technique skills recommend the next step — all routing goes through the orchestrator
- Skills that achieve RCE route to host discovery for privilege escalation

## Planned Skills

Future skill development is planned in these areas:

- **Active Directory** (6 skills) — ADIDNS poisoning, DCOM lateral movement, RODC exploitation, named CVEs (NoPAC/PrintNightmare/ZeroLogon), MSSQL AD abuse, deployment targets (MDT/WSUS/SCOM)
- **Infrastructure** — cloud (AWS/Azure), CI/CD pipeline attacks
- **Red Team** — C2 frameworks, initial access, persistence, credential dumping
- **Supplemental** — hash cracking, shell cheatsheet, database attacks, binary exploitation
