# Attackbox Dependencies

Tools referenced by red-run skills that must be available before an engagement.
Agents cannot download files or installers from the internet during execution —
everything must be pre-installed or staged on the attackbox.

## Bundled (installed by `install.sh`)

These are installed automatically. No operator action needed.

| Tool | Location | Provided by |
|------|----------|-------------|
| Impacket (all scripts) | Docker: `red-run-shell` + attackbox | `pip install impacket` in image; also needed locally via `pipx install impacket` |
| evil-winrm | Docker: `red-run-shell` | `gem install evil-winrm` in image |
| Responder | Docker: `red-run-shell` `/opt/Responder/` | git clone in image |
| mitm6 | Docker: `red-run-shell` | `pip install mitm6` in image |
| chisel (proxy) | Docker: `red-run-shell` `/usr/local/bin/chisel` | Binary download in image |
| ligolo-ng (proxy) | Docker: `red-run-shell` `/usr/local/bin/ligolo-proxy` | Binary download in image |
| socat | Docker: `red-run-shell` | apt in image |
| tcpdump | Docker: `red-run-shell` | apt in image |
| nmap | Docker: `red-run-nmap` | Alpine package in image |
| Chromium | Playwright managed | `playwright install chromium` |

## Attackbox tools (operator must install)

Tools that run on the attackbox (Linux). Organized by category with installation
commands for Kali/Debian-based systems. Many are pre-installed on Kali.

**All tools must be in `$PATH`.** Agents find tools via `command -v` / `which`.
For git-cloned repos, symlink the main script into `~/.local/bin/` or wherever
your PATH points. Run `bash preflight.sh` to verify.

### Network scanning and enumeration

| Tool | Skills | Install |
|------|--------|---------|
| nmap | network-recon | `sudo apt install nmap` (also in Docker, but useful locally) |
| nuclei | network-recon, web-discovery | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| httpx | network-recon, web-discovery | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| NetExec (nxc) | network-recon, ad-discovery, credential-dumping, kerberos-roasting, pass-the-hash, password-spraying, smb-exploitation, many AD skills | `pipx install netexec` |
| enum4linux-ng | network-recon, password-spraying | `pipx install enum4linux-ng` |
| manspider | ad-discovery, gpo-abuse | `pipx install manspider` |
| snmpwalk | network-recon | `sudo apt install snmp` |
| onesixtyone | network-recon | `sudo apt install onesixtyone` |

### Web application testing

| Tool | Skills | Install |
|------|--------|---------|
| ffuf | web-discovery | `go install github.com/ffuf/ffuf/v2@latest` |
| Burp Suite | web-discovery, most web exploitation skills | Optional but recommended for proxy capture; install from PortSwigger packages or tarball |
| sqlmap | sql-injection-union, sql-injection-error, sql-injection-blind, sql-injection-stacked | `sudo apt install sqlmap` |
| wpscan | web-discovery | `sudo gem install wpscan` |
| git-dumper | web-discovery, command-injection | `pipx install git-dumper` |
| arjun | web-discovery | `pipx install arjun` |
| paramspider | web-discovery | `pipx install paramspider` |
| commix | command-injection | `sudo apt install commix` or git clone |
| dalfox | xss-reflected | `go install github.com/hahwul/dalfox/v2@latest` |
| XSStrike | xss-reflected | `git clone https://github.com/s0md3v/XSStrike.git` |
| sstimap | ssti-jinja2, ssti-freemarker, ssti-twig | `pipx install sstimap` |
| tplmap | ssti-jinja2, ssti-freemarker, ssti-twig | `git clone https://github.com/epinna/tplmap.git` |
| TInjA | ssti-jinja2, ssti-freemarker, ssti-twig | `go install github.com/Hackmanit/TInjA@latest` |
| Fenjing | ssti-jinja2 | `pipx install fenjing` |
| ssrfmap | ssrf | `git clone https://github.com/swisskyrepo/SSRFmap.git` |
| gopherus | ssrf | `git clone https://github.com/tarunkant/Gopherus.git` |
| interactsh | xxe, ssrf, command-injection | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| xxeserv | xxe | `go install github.com/staaldraad/xxeserv@latest` |
| XXEinjector | xxe | `git clone https://github.com/enjoiz/XXEinjector.git` |
| jwt-tool | jwt-attacks | `pipx install jwt-tool` |
| domdig | xss-dom | `npm install -g domdig` |
| php_filter_chain_generator | lfi | `git clone https://github.com/synacktiv/php_filter_chain_generator.git` |

### Deserialization

| Tool | Skills | Install |
|------|--------|---------|
| ysoserial (Java) | deserialization-java | Download JAR from [GitHub releases](https://github.com/frohoff/ysoserial) |
| ysoserial.net | deserialization-dotnet | Download from [GitHub releases](https://github.com/pwntester/ysoserial.net) (Windows) |
| marshalsec | deserialization-java | `git clone https://github.com/mbechler/marshalsec.git` + `mvn package` |
| phpggc | deserialization-php | `git clone https://github.com/ambionics/phpggc.git` |
| jexboss | deserialization-java | `git clone https://github.com/joaomatosf/jexboss.git` |
| Blacklist3r | deserialization-dotnet | Download from GitHub (Windows) |
| badsecrets | deserialization-dotnet | `pipx install badsecrets` |

### Active Directory

| Tool | Skills | Install |
|------|--------|---------|
| BloodHound CE | ad-discovery, acl-abuse, kerberos-delegation, gpo-abuse | `pipx install bloodhound` (collector: `bloodhound-python`) |
| rusthound-ce | ad-discovery | Download from [GitHub releases](https://github.com/NH-RED-TEAM/RustHound-CE) |
| Certipy | adcs-template-abuse, adcs-access-and-relay, adcs-persistence, acl-abuse, ad-discovery | `pipx install certipy-ad` |
| bloodyAD | ad-discovery, acl-abuse, credential-dumping, kerberos-delegation, gpo-abuse, trust-attacks | `pipx install bloodyad` |
| kerbrute | password-spraying | Download from [GitHub releases](https://github.com/ropnop/kerbrute) |
| pywhisker | acl-abuse | `pipx install pywhisker` |
| dacledit.py | acl-abuse | Part of impacket (bundled in Docker) or `git clone https://github.com/ShutdownRepo/dacledit` |
| targetedKerberoast | kerberos-roasting | `git clone https://github.com/ShutdownRepo/targetedKerberoast` |
| krbrelayx | kerberos-delegation, auth-coercion-relay | `git clone https://github.com/dirkjanm/krbrelayx` |
| PetitPotam | adcs-access-and-relay, auth-coercion-relay, kerberos-delegation | `git clone https://github.com/topotam/PetitPotam` |
| printerbug.py | auth-coercion-relay, kerberos-delegation | Part of krbrelayx repo |
| DFSCoerce | adcs-access-and-relay, auth-coercion-relay | `git clone https://github.com/Wh04m1001/DFSCoerce` |
| ShadowCoerce | auth-coercion-relay | `git clone https://github.com/ShutdownRepo/ShadowCoerce` |
| dnstool.py | auth-coercion-relay | Part of krbrelayx repo |
| modifyCertTemplate.py | adcs-access-and-relay | `git clone https://github.com/fortalice/modifyCertTemplate` |
| gMSADumper | credential-dumping | `git clone https://github.com/micahvandeusen/gMSADumper` |
| ADFSpoof | ad-persistence | `git clone https://github.com/mandiant/ADFSpoof` |
| PKINITtools (gettgtpkinit.py) | adcs-template-abuse, adcs-access-and-relay, auth-coercion-relay | `git clone https://github.com/dirkjanm/PKINITtools` |

### SCCM

| Tool | Skills | Install |
|------|--------|---------|
| sccmhunter | sccm-exploitation | `pipx install sccmhunter` |
| pxethiefy | sccm-exploitation | `git clone https://github.com/MWR-CyberSec/PXEThief` |

### GPO

| Tool | Skills | Install |
|------|--------|---------|
| pyGPOAbuse | gpo-abuse | `git clone https://github.com/Hackndo/pyGPOAbuse` |
| GroupPolicyBackdoor | gpo-abuse | `git clone https://github.com/rootSySdk/GroupPolicyBackdoor` |
| GPOHound | gpo-abuse | `pipx install gpohound` |

### Pivoting and tunneling

| Tool | Skills | Install |
|------|--------|---------|
| sshuttle | pivoting-tunneling | `sudo apt install sshuttle` |
| proxychains | pivoting-tunneling | `sudo apt install proxychains4` |
| autossh | pivoting-tunneling | `sudo apt install autossh` |
| dnscat2 | pivoting-tunneling | `git clone https://github.com/iagox86/dnscat2.git` + `gem install bundler` |
| iodine | pivoting-tunneling | `sudo apt install iodine` |
| FRP | pivoting-tunneling | Download from [GitHub releases](https://github.com/fatedier/frp) |
| neo-reGeorg | pivoting-tunneling | `git clone https://github.com/L-codes/Neo-reGeorg` |
| rpivot | pivoting-tunneling | `git clone https://github.com/klsecservices/rpivot` |
| Metasploit | pivoting-tunneling, smb-exploitation, windows-kernel-exploits, windows-token-impersonation | `sudo apt install metasploit-framework` |

### Credential cracking

| Tool | Skills | Install |
|------|--------|---------|
| hashcat | credential-cracking | `sudo apt install hashcat` |
| john (jumbo) | credential-cracking | `sudo apt install john` |
| hydra | password-spraying | `sudo apt install hydra` |

### Evasion and payload building

| Tool | Skills | Install |
|------|--------|---------|
| mingw-w64 | av-edr-evasion, windows-service-dll-abuse, linux-file-path-abuse | `sudo apt install mingw-w64` |
| Go compiler | av-edr-evasion | `sudo apt install golang-go` |
| msfvenom | smb-exploitation, windows-kernel-exploits, windows-service-dll-abuse, windows-uac-bypass | Part of `metasploit-framework` |

### Linux privilege escalation

| Tool | Skills | Install |
|------|--------|---------|
| searchsploit | linux-kernel-exploits | `sudo apt install exploitdb` |
| gcc | linux-kernel-exploits, linux-file-path-abuse | `sudo apt install build-essential` |

### General utilities

| Tool | Skills | Install |
|------|--------|---------|
| curl | many | `sudo apt install curl` |
| openssl | jwt-attacks, adcs-persistence, credential-dumping, xmpp-enumeration | `sudo apt install openssl` |
| ldapsearch | ad-discovery, password-spraying | `sudo apt install ldap-utils` |
| rpcclient | password-spraying | `sudo apt install smbclient` |
| jq | multiple | `sudo apt install jq` |
| exiftool | deserialization-php | `sudo apt install libimage-exiftool-perl` |
| ruby | dnscat2, XXEinjector | `sudo apt install ruby` |
| Java runtime | ysoserial, marshalsec | `sudo apt install default-jdk` |
| Python 3 | many | Pre-installed on most distros |
| tmux | pivoting-tunneling | `sudo apt install tmux` |

## Wordlists

| Resource | Skills | Expected path |
|----------|--------|---------------|
| SecLists | web-discovery, password-spraying, jwt-attacks | `/usr/share/seclists/` (`sudo apt install seclists`) |
| rockyou.txt | credential-cracking, jwt-attacks | `/usr/share/wordlists/rockyou.txt` |
| jwt-secrets | jwt-attacks | `git clone https://github.com/wallarm/jwt-secrets` |

Key SecLists paths used by skills:

- `Discovery/Web-Content/raft-small-words.txt`
- `Discovery/Web-Content/quickhits.txt`
- `Discovery/Web-Content/api/api-endpoints.txt`
- `Discovery/Web-Content/burp-parameter-names.txt`
- `Discovery/DNS/subdomains-top1million-5000.txt`
- `Passwords/Common-Credentials/500-worst-passwords.txt`
- `Passwords/Common-Credentials/10k-most-common.txt`
- `Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`

## Target-side tools (not installed on attackbox)

These are transferred to targets during engagements. Download them to the
attackbox ahead of time and ensure they're in `$PATH` so agents can find them.
Agents will not download these — they expect them pre-staged.

### Linux target tools

| Tool | Skills | Source |
|------|--------|--------|
| LinPEAS (linpeas.sh) | linux-discovery | [GitHub releases](https://github.com/peass-ng/PEASS-ng) |
| linux-smart-enumeration (lse.sh) | linux-discovery | [GitHub](https://github.com/diego-treitos/linux-smart-enumeration) |
| LinEnum | linux-discovery | [GitHub](https://github.com/rebootuser/LinEnum) |
| pspy | linux-cron-service-abuse, linux-discovery | [GitHub releases](https://github.com/DominicBreuker/pspy) |
| linux-exploit-suggester | linux-kernel-exploits, linux-discovery | [GitHub](https://github.com/The-Z-Labs/linux-exploit-suggester) |
| deepce | container-escapes | [GitHub](https://github.com/stealthcopter/deepce) |
| CDK | container-escapes | [GitHub releases](https://github.com/cdk-team/CDK) |
| amicontained | container-escapes | [GitHub releases](https://github.com/genuinetools/amicontained) |
| chisel (agent) | pivoting-tunneling | [GitHub releases](https://github.com/jpillora/chisel) (Linux + Windows builds) |
| ligolo-ng (agent) | pivoting-tunneling | [GitHub releases](https://github.com/nicocha30/ligolo-ng) (Linux + Windows builds) |
| socat (static) | pivoting-tunneling | Static build for target transfer |

### Windows target tools

| Tool | Skills | Source |
|------|--------|--------|
| WinPEAS (winpeas.exe) | windows-discovery | [GitHub releases](https://github.com/peass-ng/PEASS-ng) |
| Seatbelt | windows-discovery | [GitHub](https://github.com/GhostPack/Seatbelt) (compile with VS) |
| PrivescCheck | windows-discovery | [GitHub](https://github.com/itm4n/PrivescCheck) |
| PowerUp | windows-discovery, windows-service-dll-abuse, windows-uac-bypass | Part of [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) |
| RunasCs.exe | credential context enumeration (run commands as another user) | [GitHub releases](https://github.com/antonioCoco/RunasCs) |
| Rubeus | kerberos-ticket-forging, kerberos-delegation, pass-the-hash, trust-attacks, ad-persistence | [GitHub](https://github.com/GhostPack/Rubeus) (compile with VS) |
| mimikatz | ad-persistence, credential-dumping, pass-the-hash, kerberos-ticket-forging, windows-credential-harvesting, windows-token-impersonation | [GitHub releases](https://github.com/gentilkiwi/mimikatz) |
| SharpDPAPI | windows-credential-harvesting, adcs-persistence | [GitHub](https://github.com/GhostPack/SharpDPAPI) (compile with VS) |
| SharpChrome | windows-credential-harvesting | Part of SharpDPAPI repo |
| SharpGPOAbuse | gpo-abuse | [GitHub](https://github.com/FSecureLABS/SharpGPOAbuse) (compile with VS) |
| SharpSCCM | sccm-exploitation | [GitHub](https://github.com/Mayyhem/SharpSCCM) (compile with VS) |
| Certify | adcs-template-abuse, adcs-access-and-relay | [GitHub](https://github.com/GhostPack/Certify) (compile with VS) |
| ForgeCert | ad-persistence, adcs-persistence | [GitHub](https://github.com/GhostPack/ForgeCert) (compile with VS) |
| JuicyPotato | windows-token-impersonation | [GitHub releases](https://github.com/ohpe/juicy-potato) (x64 only) |
| JuicyPotatoNG | windows-token-impersonation | [GitHub releases](https://github.com/antonioCoco/JuicyPotatoNG) |
| PrintSpoofer | windows-token-impersonation | [GitHub releases](https://github.com/itm4n/PrintSpoofer) (x64 + x86) |
| GodPotato | windows-token-impersonation | [GitHub releases](https://github.com/BeichenDream/GodPotato) (NET4 + NET35) |
| EfsPotato | windows-token-impersonation | [GitHub](https://github.com/zcgonvh/EfsPotato) (compile from source) |
| SigmaPotato | windows-token-impersonation | [GitHub releases](https://github.com/tylerdotrar/SigmaPotato) |
| PrintNotifyPotato | windows-token-impersonation | [GitHub releases](https://github.com/BeichenDream/PrintNotifyPotato) (when Spooler disabled) |
| RoguePotato | windows-token-impersonation | [GitHub](https://github.com/antonioCoco/RoguePotato) |
| FullPowers | windows-token-impersonation | [GitHub](https://github.com/itm4n/FullPowers) |

**Potato binaries staging:** Pre-download to `/usr/share/windows-binaries/potatoes/` so agents
can find and transfer them during engagements. Run `bash preflight.sh --target-tools` to check.

```bash
sudo mkdir -p /usr/share/windows-binaries/potatoes && cd /usr/share/windows-binaries/potatoes
sudo curl -sLO https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
sudo curl -sLO https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET35.exe
sudo curl -sLO https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
sudo curl -sLO https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe
sudo curl -sLO https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip && sudo unzip -o JuicyPotatoNG.zip && sudo rm JuicyPotatoNG.zip
sudo curl -sLO https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
sudo curl -sLO https://github.com/BeichenDream/PrintNotifyPotato/releases/download/v1.00/PrintNotifyPotato-NET46.exe
```
| Watson | windows-kernel-exploits, windows-discovery | [GitHub](https://github.com/rasta-mouse/Watson) (compile with VS) |
| WES-NG | windows-kernel-exploits, windows-discovery | `pipx install wesng` (runs on attackbox, analyzes systeminfo output) |
| SpoolSample | kerberos-delegation, auth-coercion-relay | [GitHub](https://github.com/leechristensen/SpoolSample) (compile with VS) |
| StandIn | acl-abuse, gpo-abuse | [GitHub](https://github.com/FuzzySecurity/StandIn) (compile with VS) |
| SessionGopher | windows-credential-harvesting | [GitHub](https://github.com/Arvanaghi/SessionGopher) |
| ADFSDump | ad-persistence | [GitHub](https://github.com/mandiant/ADFSDump) |
| MalSCCM | sccm-exploitation | [GitHub](https://github.com/nettitude/MalSCCM) |
| PowerView | ad-discovery, acl-abuse, kerberos-roasting, gpo-abuse, trust-attacks | Part of [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) |
| Invoke-PowerShellTcp.ps1 | orchestrator (reverse shells) | Part of [nishang](https://github.com/samratashok/nishang) |
| accesschk | windows-service-dll-abuse, windows-discovery | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) |
| procdump | windows-token-impersonation | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) |

## Quick setup (Kali)

Most tools are pre-installed on Kali Linux. This covers the common gaps:

```bash
# Go tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest

# Python tools (pipx)
pipx install impacket
pipx install netexec
pipx install certipy-ad
pipx install bloodyad
pipx install manspider
pipx install git-dumper
pipx install sccmhunter
pipx install badsecrets
pipx install sstimap
pipx install gpohound
pipx install wesng

# Apt packages (if not already on Kali)
sudo apt install -y seclists mingw-w64 golang-go hashcat john hydra \
    sshuttle proxychains4 autossh iodine tmux jq ldap-utils \
    libimage-exiftool-perl default-jdk exploitdb

# Git repos — clone wherever you like, then add scripts to $PATH
# (e.g., symlink main scripts into ~/.local/bin/)
git clone https://github.com/dirkjanm/krbrelayx
git clone https://github.com/dirkjanm/PKINITtools
git clone https://github.com/topotam/PetitPotam
git clone https://github.com/Wh04m1001/DFSCoerce
git clone https://github.com/ShutdownRepo/ShadowCoerce
git clone https://github.com/ShutdownRepo/targetedKerberoast
git clone https://github.com/Hackndo/pyGPOAbuse
git clone https://github.com/micahvandeusen/gMSADumper
git clone https://github.com/fortalice/modifyCertTemplate
git clone https://github.com/synacktiv/php_filter_chain_generator
git clone https://github.com/ambionics/phpggc
git clone https://github.com/frohoff/ysoserial       # needs mvn build
git clone https://github.com/mbechler/marshalsec      # needs mvn build
git clone https://github.com/swisskyrepo/SSRFmap
git clone https://github.com/s0md3v/XSStrike
git clone https://github.com/epinna/tplmap
git clone https://github.com/wallarm/jwt-secrets

# Download binary releases and add to $PATH
# kerbrute, pspy, linpeas, winpeas, chisel (agent builds),
# ligolo-ng (agent builds), GodPotato, PrintSpoofer, JuicyPotato,
# CDK, deepce — download from their GitHub releases pages
```
