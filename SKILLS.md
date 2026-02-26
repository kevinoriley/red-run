# Skills Inventory

63 skills across 6 categories. All skills are `SKILL.md` files under `skills/`.

## Web Application (30 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `web-discovery` | Content discovery, parameter fuzzing, vulnerability routing | 682 |
| `sql-injection-union` | UNION-based extraction (MySQL, MSSQL, Postgres, Oracle, SQLite) | 349 |
| `sql-injection-error` | Error-based extraction (EXTRACTVALUE, CONVERT, CAST) | 303 |
| `sql-injection-blind` | Boolean, time-based, OOB blind extraction | 364 |
| `sql-injection-stacked` | Stacked queries, second-order injection, command execution | 367 |
| `xss-reflected` | Reflected XSS, filter/WAF/CSP bypass, impact demonstration | 404 |
| `xss-stored` | Stored + blind XSS, callback setup, self-XSS escalation | 344 |
| `xss-dom` | DOM-based XSS, sources/sinks, postMessage, DOM clobbering | 416 |
| `ssti-jinja2` | Jinja2/Python SSTI (+ Mako, Tornado, Django) | 409 |
| `ssti-twig` | Twig/PHP SSTI (+ Smarty, Blade, Latte) | 386 |
| `ssti-freemarker` | Freemarker/Java SSTI (+ Velocity, SpEL, Thymeleaf, Pebble, Groovy) | 446 |
| `ssrf` | Basic/blind SSRF, cloud metadata, filter bypass, gopher/dict protocol | 564 |
| `lfi` | LFI, PHP wrappers, 8 LFI-to-RCE methods, filter bypass, RFI | 571 |
| `command-injection` | OS command injection, filter bypass, blind techniques, argument injection, credential handoff | 545 |
| `xxe` | Classic/blind/OOB XXE, error-based (remote + local DTD), XInclude, file format injection | 515 |
| `file-upload-bypass` | Extension/content-type/magic byte bypass, config exploitation, polyglots, archive traversal | 549 |
| `deserialization-java` | ysoserial gadget chains, JNDI/Log4Shell, JSF ViewState, WebLogic/JBoss/Jenkins | 449 |
| `deserialization-php` | Magic methods, POP chains, PHPGGC, phar:// polyglots, Laravel APP_KEY, type juggling | 410 |
| `deserialization-dotnet` | ysoserial.net, ViewState/machine keys, JSON.NET TypeNameHandling, .NET Remoting | 455 |
| `jwt-attacks` | alg:none, key confusion, kid injection, jwk/jku spoofing, secret brute force, claim tampering | 581 |
| `request-smuggling` | CL.TE, TE.CL, TE.TE obfuscation, H2 downgrade, h2c smuggling, response desync, cache poisoning | 590 |
| `nosql-injection` | MongoDB operator injection, auth bypass, blind regex extraction, $where JS execution, Mongoose RCE | 544 |
| `ldap-injection` | LDAP filter injection, wildcard auth bypass, blind attribute extraction, filter breakout, AD/OpenLDAP | 615 |
| `idor` | Horizontal/vertical access control bypass, UUID/ObjectId prediction, API IDOR, encoding bypass | 596 |
| `cors-misconfiguration` | Origin reflection, null origin, regex bypass, subdomain trust, wildcard abuse, CORS+IDOR chain | 591 |
| `csrf` | Token bypass, SameSite bypass, JSON CSRF, file upload CSRF, WebSocket CSRF, clickjacking chain | 636 |
| `oauth-attacks` | Redirect URI bypass, state bypass, code theft, token leakage, OIDC attacks, PKCE bypass, ATO chains | 636 |
| `password-reset-poisoning` | Host header poisoning, Referer token leakage, email injection, token weakness, brute-force | 559 |
| `2fa-bypass` | Response manipulation, direct navigation, OTP brute-force, backup codes, OAuth bypass, session attacks | 610 |
| `race-condition` | Limit-overrun, HTTP/2 single-packet, last-byte sync, Turbo Intruder, TOCTOU, rate limit bypass | 742 |

## Active Directory (16 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `ad-discovery` | Domain enumeration (BloodHound, LDAP, NetExec), attack surface mapping, routing to 15 technique skills | 587 |
| `kerberos-roasting` | Kerberoasting + AS-REP Roasting + Timeroasting, targeted kerberoasting via ACL abuse | 480 |
| `password-spraying` | Lockout-safe domain spray (Kerberos/NTLM/OWA), policy enumeration, smart password generation | 537 |
| `pass-the-hash` | PTH, Over-Pass-the-Hash, Pass-the-Key (AES), Pass-the-Ticket, lateral movement tools | 500 |
| `kerberos-delegation` | Unconstrained (TGT harvesting + coercion), Constrained (S4U + SPN swapping), RBCD | 533 |
| `kerberos-ticket-forging` | Golden, Silver, Diamond, Sapphire tickets + Pass-the-Ticket injection | 484 |
| `acl-abuse` | GenericAll/Write, WriteDACL, WriteOwner, shadow credentials, AdminSDHolder persistence | 578 |
| `adcs-template-abuse` | ESC1/2/3/6 — SAN manipulation, any-purpose EKU, enrollment agent, EDITF flag abuse | 486 |
| `adcs-access-and-relay` | ESC4/5/7/8/11 — template/CA ACL abuse, NTLM relay to HTTP/RPC enrollment | 520 |
| `adcs-persistence` | ESC9-15, Golden Certificate, certificate theft (DPAPI/CAPI/CNG), cert mapping persistence | 629 |
| `auth-coercion-relay` | PetitPotam/PrinterBug/DFSCoerce coercion, NTLM relay (LDAP/SMB/ADCS/MSSQL), Kerberos relay, LLMNR/NBNS poisoning | 632 |
| `credential-dumping` | DCSync, NTDS extraction, SAM dump, LAPS (legacy + Windows), gMSA/GoldenGMSA, dMSA BadSuccessor, DSRM | 626 |
| `gpo-abuse` | GPO exploitation (SharpGPOAbuse/pyGPOAbuse/GroupPolicyBackdoor), SYSVOL script poisoning, GPP passwords | 555 |
| `trust-attacks` | Trust enumeration, SID history injection (child to forest root), inter-realm TGT forging, PAM trust/shadow principals, cross-forest abuse | 488 |
| `sccm-exploitation` | SCCM enumeration (sccmhunter/SharpSCCM), NAA credential extraction, MP relay to MSSQL, client push relay, PXE boot harvesting, app deployment | 550 |
| `ad-persistence` | DCShadow, Skeleton Key, custom SSP (mimilib/memssp), security descriptor backdoors, ADFS Golden SAML, SID history persistence, golden certificate | 617 |

All AD skills follow a **Kerberos-first authentication** convention — commands default to ccache-based Kerberos auth to avoid NTLM detection signatures (Event 4776, CrowdStrike Identity Module). Exception: relay/coercion attacks are inherently NTLM/network-level.

## Privilege Escalation (11 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `windows-discovery` | WinPEAS/PowerUp/Seatbelt/Watson enumeration, OPSEC-safe privilege checks, routing to 5 technique skills | 590 |
| `windows-token-impersonation` | Potato family (7+ variants by OS version), SeDebug/SeBackup/SeRestore/SeLoadDriver/SeManageVolume exploitation, FullPowers | 524 |
| `windows-service-dll-abuse` | Unquoted paths, weak service perms, DLL search order hijacking, DLL proxying, COM hijacking, service triggers, auto-updater abuse | 557 |
| `windows-uac-bypass` | Fodhelper/eventvwr/sdclt/SilentCleanup/CMSTP/WSReset, COM hijacking, AlwaysInstallElevated MSI, autorun exploitation | 585 |
| `windows-credential-harvesting` | HiveNightmare, DPAPI (SharpDPAPI/mimikatz/dpapi.py), browser creds, PS history, unattend files, vaults, cloud creds | 563 |
| `windows-kernel-exploits` | PrintNightmare/EternalBlue/MS16-032/MS15-051, BYOVD/loldrivers.io, privileged file write/delete, named pipes, leaked handles | 641 |
| `linux-discovery` | LinPEAS/LinEnum/pspy/lse enumeration, system info, sudo/SUID/capabilities/cron assessment, routing to 4 technique skills | 664 |
| `linux-sudo-suid-capabilities` | Sudo NOPASSWD/LD_PRELOAD/CVE-2021-3156/CVE-2019-14287, SUID GTFOBins, shared object injection, 20+ Linux capabilities | 631 |
| `linux-cron-service-abuse` | Cron script hijack, tar/chown/rsync wildcard injection, systemd timer/service abuse, D-Bus command injection, PwnKit/CVE-2021-3560, Unix sockets | 683 |
| `linux-file-path-abuse` | Writable /etc/passwd+shadow+sudoers, NFS no_root_squash, Docker/LXD/disk group escape, library hijacking, PATH hijack, profile injection | 861 |
| `linux-kernel-exploits` | DirtyPipe/DirtyCow/GameOver(lay)/10+ CVEs, exploit suggesters, attackbox-first transfer, restricted shell escape, chroot escape, container kernel escape | 1025 |

## Infrastructure (4 skills)

| Skill | Technique | Lines |
|-------|-----------|-------|
| `network-recon` | Passive recon, host discovery, nmap full scan, 20+ protocol service enumeration with quick wins, OS fingerprinting, vuln scanning, routing | 974 |
| `pivoting-tunneling` | SSH tunneling (L/R/D/J/sshuttle/VPN), Ligolo-ng, Chisel, socat, Windows pivoting, DNS/ICMP/HTTP tunneling, multi-hop, tool compatibility | 1165 |
| `container-escapes` | Docker socket/privileged/cgroup escape, sensitive mounts, capability abuse, K8s SA token/RBAC/etcd/kubelet exploitation, container CVEs, cloud metadata | 1041 |
| `smb-exploitation` | MS08-067, MS17-010/EternalBlue, MS09-050, SMBGhost, OS compatibility matrix, Metasploit target selection, standalone Python fallback | 417 |

## Utility (2 skills)

| Skill | Purpose | Lines |
|-------|---------|-------|
| `orchestrator` | Takes a target, runs recon, routes to discovery skills, chains vulnerabilities via state management | 462 |
| `retrospective` | Post-engagement lessons-learned analysis, skill routing gaps, actionable improvements | 247 |

## Planned

- **Active Directory** (6 extended) — ADIDNS poisoning, DCOM lateral movement, RODC exploitation, named CVEs (NoPAC/PrintNightmare/ZeroLogon), MSSQL AD abuse, deployment targets (MDT/WSUS/SCOM)
- **Infrastructure** (extended) — cloud (AWS/Azure), CI/CD
- **Red Team** — C2, initial access, evasion, persistence, credential dumping
- **Supplemental** — hash cracking, shell cheatsheet, database attacks, binary exploitation
