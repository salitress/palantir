# palantir

[![selftest](https://github.com/salitress/palantir/actions/workflows/selftest.yml/badge.svg)](https://github.com/salitress/palantir/actions/workflows/selftest.yml)
[![Release](https://img.shields.io/github/v/tag/salitress/palantir?label=release)](https://github.com/salitress/palantir/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/salitress/palantir)](https://github.com/salitress/palantir/stargazers)
[![Español](https://img.shields.io/badge/README-Español-red.svg)](README.es.md)

**Nmap-driven recon automation for authorized labs and engagements (OSCP / CPTS / HTB).**
Ports, service fingerprinting, **per-protocol footprinting**, **known-exploit
lookup** and web surface — before you touch anything. Single Python 3 file,
**stdlib-only core**; every external tool is **optional** and skipped
gracefully if missing: `nmap` (required), `ffuf` (web fuzzing), `searchsploit`
(known exploits), and for footprinting: `nxc`/`netexec` (SMB, LDAP, WinRM,
RDP, VNC, WMI, MSSQL, NFS), `smbclient`/`rpcclient`/`smbmap`/`enum4linux-ng`,
`impacket-rpcdump`, `showmount`, `dig`, `whois`, `crt.sh` (Certificate
Transparency), `ldapsearch`, `whatweb`, `wafw00f`, `snmpwalk`/`onesixtyone`,
`tnscmd10g`, `redis-cli`, `certipy` (AD CS template abuse), `impacket-
GetNPUsers`/`GetUserSPNs` (AS-REP roast / Kerberoasting), `adidnsdump`
(internal DNS over LDAP). Built for Kali.

> **Heads up:** the tool's own output — CLI messages, the HTML/Markdown
> report, every code comment — is in **Spanish**. That's intentional: it's
> where this project started, and it stays that way. This README is fully
> translated so the project itself is discoverable in English; the two
> READMEs are kept at parity on purpose — see **[README.es.md](README.es.md)**
> for the native-language version.

## Contents

[Preview](#preview) · [Why](#why) · [Quick start](#quick-start) ·
[What it does](#what-it-does) · [Requirements](#requirements) ·
[Usage](#usage) · [Flags](#flags) · [Pivoting / tunneling](#pivoting--tunneling) ·
[Notes](#notes) · [Safe for exam use](#safe-for-exam-use)

## Preview

![report.html example: summary cards, Quick wins, findings by severity, jump-to-section index](img/report-example.png)

*Illustrative example (synthetic data, generated for this README) — this is
what `report.html` looks like after a real scan: summary cards up top,
**★ Quick wins** with a copy button on every command, findings sorted by
severity, and a **"Jump to:"** index into every protocol section.*

## Why

Most recon workflows for OSCP/CPTS-style labs end up as a pile of one-off
`nmap`/`nxc`/`ffuf` commands copy-pasted from a cheat sheet, re-typed for
every box. `palantir` automates the *safe, read-only* part of that
workflow — discovery, fingerprinting, default-credential checks, known-exploit
lookup, web fuzzing — and stops exactly where exploitation starts, leaving
every "next step" as an explicit, ready-to-copy command instead of running it
for you. See [Safe for exam use](#safe-for-exam-use) for why that boundary is
drawn where it is.

## Quick start

```bash
sudo ./palantir.py 10.129.21.27          # full recon by default (see "What it does" below)
```

The flags you'll actually reach for day to day (full table in [Flags](#flags)):

| Flag | What it's for |
|---|---|
| `target` | IP, CIDR, range or hostname — the only required argument. |
| `sudo` | SYN scan (`-sS`) + UDP. Without root, falls back to connect scan (`-sT`), slower. |
| `--top` | Top-1000 ports instead of all 65535 — much faster for a first pass. |
| `--no-aggressive` | Skip `vuln` NSE scripts and deep footprinting — faster, quieter. |
| `--stealth` | Slower, quieter timing — for evasion-focused labs. |
| `--tunnel` (`--pivoting`) | Scan through a pivot/tunnel (ligolo-ng, chisel, SOCKS...): `-sT` + timing tuned not to flood the relay (no `--min-rate`, more retries) so you don't silently lose open ports. Much faster than `--stealth`. |
| `--resume` | Reuses the existing nmap scan and, if ports didn't change, the previous footprint/searchsploit/default-creds results too (not repeated) — only reruns fuzzing/reports and any newly provided credentials. For fast iteration. |
| `--vhost DOMAIN` / `--vhost-names LIST` | Vhost fuzzing, or go straight to confirming ones you already know. |
| `--port PORTS` | When you already know the port (e.g. an HTB Academy lab) — skips the full sweep. |
| `--default-creds` | **Only** verified default credentials, nothing else — fast and targeted. |
| `--jobs N` | Multiple targets in parallel (a `/24`, a large list). |
| `-o DIR` | Output folder (default `~/htb`). |
| `--selftest` | Runs the tool's own test suite without touching the network. |

More copy-paste examples in [Usage](#usage).

## What it does

0. **Ping sweep** (CIDR/ranges, `nmap -sn`, one process) — checks who's alive
   first and drops dead hosts from the rest of the run (a /24 with 50 live
   hosts saves 200 full `-p-` sweeps against dead ones). Only prunes IPs that
   came from a CIDR/range; a single IP or hostname given by hand is always
   scanned (an HTB box often doesn't answer ping, hence `-Pn` for the rest).
   `--no-sweep` disables it (targets that block ICMP). **Auto-disabled under
   `--tunnel`**: ICMP rarely crosses a pivot/SOCKS, so trying it there would
   report "everyone's dead" instead of actually pruning anything.
1. **Port discovery** — full `-p- --min-rate --max-retries 2 --open` sweep.
   Top-1000 with `--top`.
2. **Enumeration** — `-sV` + a curated list of **safe** NSE scripts on open
   ports (nmap routes each script to its service via its portrule), with
   `--script-timeout`. With `--aggressive`, a **second, separate** nmap run
   adds `vuln`/backdoor scripts (heartbleed, ms17-010, shellshock...), so a
   hang in one of those — and its timeout — never costs you the safe
   results. No `dos`/`unsafe`, no `vulners` (doesn't phone home).
3. **UDP** (optional, `--udp`, needs root) — a sweep of the UDP ports that
   matter (SNMP 161, TFTP 69, NTP 123, IPMI 623, DNS 53...) with `-sV
   --version-intensity 0`. Right after enumeration and before banner
   grabbing/footprinting, so SNMP/IPMI over UDP are already available when
   phase 5 footprints them.
4. **Manual banner grabbing** — a raw socket probe against every open port,
   catching services nmap left as `unknown` (e.g. an FTP on 31337 that
   answers `220 ...`). The HTTP `HEAD` probe only goes to web ports.
5. **Per-protocol footprinting** — for every recognized service, the manual
   enumeration that covers the CPTS Footprinting path: **read-only and
   default credentials only** (anonymous / null / guest / `Administrator`
   with no password / `sa` with no password / `public`): **one attempt per
   account**, never password brute force, never a write to the target. Every
   command is printed with its *why*. `nxc` protocols share a **default-
   credential fallback chain** (`null → guest → Administrator`), and
   `(Pwn3d!)` is always a critical finding. One line per protocol:

   | Protocol / port | What happens |
   |---|---|
   | FTP | Anonymous login + listing (`ftplib`); **mod_copy** (ProFTPD, CVE-2015-3306: unauthenticated `SITE CPFR` → RCE, read-only) and **FTP bounce** (NSE `ftp-bounce`). |
   | SMB / RPC | Null-session `smbclient`/`rpcclient` (incl. **`enumdomgroups` + membership** of Domain Admins/custom groups via SAMR, no credentials needed), `nxc` with the default-credential fallback, content spidering of readable shares (`--spider`); **Zerologon** (CVE-2020-1472, no credentials), **SMB signing not required** (NTLM relay surface, combined with MSRPC) and full AD enum if it's a DC **and** a session gets in. With `-u/-p/-H` (phase 5d): enum WITH the credential + **`--loggedon-users`** + **GPP cpassword** in SYSVOL + **noPac** (CVE-2021-42278/42287, standard domain account → Domain Admin). |
   | LDAP | `nxc` with fallback (if the bind gets in) + `ldapsearch` naming contexts/**domain-forest trusts**/**MachineAccountQuota** (`-M maq`). With a credential (phase 5d): users/groups/roasting + **LAPS** (local admin) + `certipy find` (AD CS, vulnerable templates) + **DCSync-rights** (krbtgt hash if replication rights exist) + **adidnsdump** (internal DNS over LDAP) + MAQ/trusts again with the credential. |
   | WinRM / RDP / VNC / WMI | `nxc` with the default-credential fallback. |
   | MSSQL | `nxc` with `sa`/no password → `xp_cmdshell`. |
   | NFS | `showmount` + `nxc nfs --shares`. |
   | DNS | AXFR + `dig any`; WHOIS, Certificate Transparency (`crt.sh`) and passive DNS (hackertarget.com) if a domain is known. |
   | Kerberos / Docker API | Confirms it's a DC + **real user enumeration over Kerberos** (`kerbrute userenum`, no lockout risk) if a domain is known, plus, with **`--spray PASS`**, **automatic password spraying** (`kerbrute passwordspray --safe`) against the discovered accounts; unauthenticated Docker API → trivial RCE if it answers. |
   | SMTP | `EHLO`+`VRFY`, user enumeration/open relay. |
   | IMAP / POP3 / SSH | Banner/algorithms + next steps. |
   | SNMP | `snmpwalk` + a targeted walk of juicy OIDs; community brute force with `--aggressive`. |
   | Web / IIS | `whatweb`+`wafw00f`+sensitive-file checks + missing security headers (HSTS/CSP/X-Frame-Options/X-Content-Type-Options); `--nikto`/`--cms-scan`/`--crawl`/`--nuclei` opt-in. |
   | MySQL / PostgreSQL / Oracle / IPMI / Redis / rsync | NSE + next steps. |
   | Elasticsearch / CouchDB / Memcached | Unauthenticated access. |
   | AJP / RMI / MongoDB / Telnet / TFTP / NTP | Exploitation next steps / NSE. |
   | Finger / IPP-CUPS / X11 / git daemon | Unauthenticated user enum (`finger`) / CUPS version (CVE-2024-47176 chain) / open display `xhost +` (screenshot/keylogging) / clonable exported repos without auth. |

   <details>
   <summary><b>Full detail per protocol</b> (click to expand)</summary>

   - **FTP** → anonymous login + `LIST` (via `ftplib`, no external binary needed; works where nmap's `ftp-anon` fails against a non-standard FTP).
   - **SMB / RPC** → `smbclient -N -L`, null-session `rpcclient`, `nxc smb --shares` with a null/guest/Administrator fallback; **content spidering of readable shares** (`smbclient recurse ON; ls`, read-only) flagging juicy files (keys, configs, GPP `Groups.xml`, backups, flags...); if it's a **Domain Controller** (Kerberos/LDAP), **Zerologon** (`nxc smb -M zerologon`, CVE-2020-1472, **no credentials needed**, against any DC — confirms, doesn't exploit; if it comes back VULNERABLE it's usually the shortest path to Domain Admin in the whole run) and, **if any anonymous session got in** (null/guest), **read-only AD enum**: `--rid-brute` (users via IPC$) and, **only if that session actually returns real data** (RID cycling pulls users, or `--shares` already showed a readable share), `--users`, `--computers`, `--pass-pol` (minimum length, complexity, history and lockout always come back as an `info` finding — it used to only fire when lockout was weak — with a separate warning if there's no account lockout at all). Without `nxc`/`netexec`, `rpcclient getdompwinfo` (added to the `rpcclient` chain above at zero extra cost) still gets minimum length + complexity from a null session. That same null-session `rpcclient` chain also runs **`enumdomgroups`** and, on a DC, for the **high-value** groups (Domain/Enterprise/Schema Admins, GPO Creators) and the domain's **custom** groups (RID≥1000, e.g. `Interns`), queries their **membership** with `querygroupmem` and resolves member RIDs to names already returned by `enumdomusers`/`enumdomgroups` (no extra calls) — knowing **who** is a Domain Admin without any credentials at all, something neither `nxc`'s RID cycling nor a bare `enumdomusers` gave you. A modern DC **accepts** the null/anonymous session (`[+]`) but then **denies every read** (RestrictAnonymous): in that case `[+]` only means "session accepted", not "authorized", so palantir doesn't insist with `--users/--computers/--pass-pol` (they'd return nothing anyway) and flags that credentials are needed instead. Same if null/guest don't get in at all. **SMB signing**: read from `nxc`'s banner (which it ALWAYS prints, even if the login fails) — if it's NOT required, `media` finding; if MSRPC (below) also confirms a coercion primitive (MS-RPRN/PrinterBug or MS-EFSR/PetitPotam) on the SAME host, palantir escalates to a CRITICAL **reflective relay** finding: coercing the machine to authenticate to a listener you control and relaying that same authentication straight back to its OWN SMB with `ntlmrelayx` gets you a session as that machine's own computer account, without cracking or stealing any password (the combination happens after the full footprint, in `run_one`, so it works the same on a fresh run as after `--resume`). With **`--spider`**, **content** spidering (`nxc --spider SHARE --content`, grepping inside files) of readable shares. With `--aggressive`, `enum4linux-ng -A`. With a domain credential (phase 5d, see below) it also looks for **GPP cpassword** in SYSVOL (`-M gpp_password`/`gpp_autologin`, MS14-025: old GPO passwords encrypted with an AES key Microsoft published) and checks **noPac** (`-M nopac`, CVE-2021-42278/42287: with ANY domain account, no admin needed, confirms whether the DC lets you impersonate a Domain Admin).
   - **LDAP** → `nxc ldap` with fallback: `--users` is the **probe**, and `--groups`/`--pass-pol`/`-M get-desc-users`/**`-M maq`** only fire **if that `--users` actually returns users** (an anonymous bind the DC accepts but doesn't authorize to read returns nothing — palantir then flags that credentials are needed instead of insisting with flags that would return the same nothing) + `ldapsearch` naming contexts/**trusts**. **MachineAccountQuota** (`-M maq`): if MAQ>0 (Microsoft's default is 10), ANY domain account can create machine accounts — a precondition for noPac/RBCD/Shadow Credentials (`alta` finding); MAQ=0 is the recommended hardening (`info`). **Domain/forest trusts**: `nxc` has NO `--trusts` flag for ldap (confirmed by reading its source — the method exists but no CLI argument calls it), so palantir uses `ldapsearch` instead (same base DN as `namingContexts`, READ-ONLY): direction, type, and whether the trust spans the partner's ENTIRE forest (key to the scope of an extra-SID/cross-forest Kerberoasting attack). With a credential (phase 5d) both repeat: MAQ via `nxc` again, trusts via a simple `ldapsearch` bind (`-D user@domain -y FILE` — plaintext secret ONLY, never with `-H`/hash, password never on argv). **`-M get-desc-users`** looks for forgotten passwords in the `description` field (a classic AD hygiene failure — a real `nxc` module, actually run, not just suggested; **phase 5d repeats it with the provided credential too**, for when anonymous bind is disabled). With a valid credential (`-u/-p/-H`), phase 5d also runs **AS-REP roasting** (`impacket-GetNPUsers ... -request`) and **Kerberoasting** (`impacket-GetUserSPNs ... -request`): each one queries the DC directly for EVERY vulnerable account (no-preauth / has-SPN) and dumps the hashes, with no dependency on a username wordlist. It also checks **LAPS** (`-M laps`: can this credential read the local admin password LAPS rotates automatically? If any domain account can, it's misconfigured — critical finding, often reused across machines), **DCSync-rights** (`secretsdump.py -just-dc-user krbtgt`: confirms replication rights by dumping ONLY that one hash, never a full NTDS — see Notes) and **adidnsdump** (internal domain DNS over LDAP, without depending on the zone allowing AXFR). That same phase 5d, with `certipy` installed and the AD domain already resolved, also runs `certipy find -vulnerable` (AD CS: READ-ONLY, enumerates CAs/templates over LDAP) — if it flags an **ESC1-8** template, that's a CRITICAL finding with the next step (`certipy req`, requesting the certificate) left as a **manual suggestion**, never chained automatically (requesting/forging a certificate is an active escalation, qualitatively the same as a full NTDS dump — see Notes).
   - **WinRM / RDP / VNC / WMI (MSRPC)** → `nxc` with the default-credential fallback; VNC checks unauthenticated access; MSRPC adds `impacket-rpcdump` (RPC endpoints) — if it exposes **MS-RPRN/MS-PAR** (network print spooler) or **MS-EFSR** (the EFSRPC interface, exposed on almost any DC by default, unlike the spooler), an `alta` finding with the `petitpotam.py`/`coercer` command ready to go (PrinterBug/PrintNightmare CVE-2021-34527 / PetitPotam CVE-2021-36942 surface) — and, if SMB also doesn't require signing (above), palantir escalates to `critica` with the exact **reflective relay** command (`ntlmrelayx.py` against the machine's own SMB).
   - **MSSQL** → `nxc mssql` with `sa`/no password (→ `xp_cmdshell` → RCE) and a null session.
   - **NFS** → `showmount -e` + `nxc nfs --shares` (exports and permissions).
   - **DNS** → `version.bind`, `dig axfr` (zone transfer) + `dig any` for every discovered domain or one passed with `--vhost`. If a domain is known (discovered, or via `--vhost`/hostname): **WHOIS** (registrar/creation-expiry dates/name servers), **Certificate Transparency** via `crt.sh` (real subdomains confirmed by an issued certificate, never guessed) and **passive DNS** via hackertarget.com (public, unauthenticated API: subdomains with a seen DNS record, even if they never had HTTPS — complements `crt.sh`) — both sources feed phase 7's vhost fuzzing before the big wordlist.
   - **Kerberos (88)** → confirms it's a Domain Controller and, if the AD domain is known (discovered, or via `--vhost`/`-D`) and `kerbrute` is installed, **really enumerates users over Kerberos pre-auth** (`kerbrute userenum`): the fallback that finds users on a **hardened DC** where null SMB / anonymous LDAP give you nothing. It's **read-only with zero lockout risk**: it sends an AS-REQ per name and checks whether the KDC says "unknown principal" or "needs pre-auth" — **it never tries a password, never increments `badPwdCount`, never locks an account** (unlike `passwordspray`). It automatically tries **`jsmith.txt`** first ([insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames): `first.last`/`flast`/`lastf`... patterns built from the most common given/family names — guesses real **employee** accounts, not just the obvious `administrator`-style ones RID cycling/anonymous enum already give you) if it's installed at `/usr/share/wordlists/statistically-likely-usernames/jsmith.txt` (not bundled in seclists; `--install-missing` downloads it on its own — see below — or install it by hand); otherwise it falls back to a **small** seclists wordlist (seconds; jsmith.txt takes minutes, not seconds, but nowhere near the hours an xato-10M run would — the time cap adjusts itself depending on which one is in use). Pass **`--userenum-wordlist`** a big one (e.g. xato-10M) if you want a thorough sweep, and **`--no-userenum`** disables it. Users found get dumped to `ad_users.txt` (ready for AS-REP roasting / spraying) and accounts with **no pre-auth** get flagged as **AS-REP roastable** (a crackable hash with zero credentials). With **`--spray PASS`** (see the flags table) palantir automatically sprays that password against those same `ad_users.txt` entries with `kerbrute passwordspray --safe` right after footprinting — no need to give it `-u`. **Docker API (2375/2376)** → a read-only GET to `/version`; if it answers unauthenticated, a CRITICAL finding with the host-mount command ready (trivial RCE).
   - **SMTP** → `EHLO` + `VRFY` (via `smtplib`); detects user enumeration and open relay.
   - **IMAP/POP3** → banner + a plaintext-mail warning (no TLS). **SSH** → algorithms/methods/hostkeys (NSE) + next steps.
   - **SNMP** → `snmpwalk -c public` and, if it answers, a **targeted walk of juicy OIDs**: processes and **their arguments** (credentials on the command line), installed software, Windows users and local ports; with `--aggressive`, `onesixtyone` (community brute force).
   - **Web / IIS** → a quick recon pass: `whatweb` (fingerprint) + NSE headers + **`wafw00f`** (WAF detection BEFORE phase 6/7 fuzz; if there's one, suggests `--stealth`); if it's **IIS/ASP.NET**, **8.3 short-name** enumeration and a **WebDAV** check. Plus an **automatic read-only check**: `OPTIONS` (which methods are actually allowed + WebDAV) and a content-**verified** GET of typical sensitive files (`trace.axd`, `elmah.axd`, `web.config`, `.git/HEAD`, `server-status`, `.env`, `phpinfo`) **and of `.well-known/security.txt` + `.well-known/openid-configuration`** — the content check avoids the false positive of a server that answers 200 to everything. **Missing security headers**: HSTS (only over https), X-Content-Type-Options, Content-Security-Policy, and X-Frame-Options **or** CSP with `frame-ancestors` (either counts — it's only a finding if both are missing, i.e. clickjacking is actually possible). Anything that **writes** to the target (`davtest`) stays a suggestion. `nikto` also stays a suggestion **unless you pass `--nikto`** (opt-in: a full vuln/config scan, several minutes per service — with the flag it actually runs and its final count becomes a finding). If `whatweb` detected **WordPress** or **Joomla**, `--cms-scan` (opt-in, same time cost) runs `wpscan`/`joomscan`: version, vulnerable plugins/themes, enumerated users. For **any other product `whatweb` recognizes with its own signature** (Jenkins, Grafana, Tomcat, phpMyAdmin, Webmin...), it's left as a **manual suggestion** to check [DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) — palantir only points you to the tool, it doesn't run the lookup for you. **`--crawl`** (opt-in) runs `katana`: follows links/JS/forms for real (doesn't guess paths like ffuf), capped at depth 2 / 60 pages. **`--nuclei`** (opt-in) runs `nuclei` (ProjectDiscovery): community templates for known CVEs, exposures and misconfigurations, filtered to `low+` severity (dropping the `info`-level tech-detection noise).
   - **MySQL / PostgreSQL / Oracle / IPMI / Redis / rsync** → consolidates NSE + next steps (`LOAD_FILE`/`INTO OUTFILE`, `COPY ... FROM PROGRAM`, `oracle-sid-brute`, `ipmi_dumphashes`, unauthenticated Redis, rsync modules).
   - **Elasticsearch (9200) / CouchDB (5984) / Memcached (11211)** → **unauthenticated**-access check (direct read: banner/indices, `_all_dbs`, `stats`) + a dump command as next step.
   - **AJP (8009) / Java RMI (1099)** → exploitation next steps (Ghostcat CVE-2020-1938; `rmi-dumpregistry`/deserialization). **MongoDB / Telnet** → anonymous access / banner + default credentials. **TFTP (69) / NTP (123)** → NSE + read-only next steps.
   - **Finger (79)** → **unauthenticated** user enumeration (a short list of typical account names, one query per name — not brute force) + the `finger` NSE script; any users found feed spraying/AS-REP/SSH (`alta` finding). **IPP / CUPS (631)** → `cups-info`/`cups-queue-info` + CUPS version (a hint at the CVE-2024-4717x `cups-browsed` chain: RCE via a malicious printer — manual verification). **X11 (6000-6009)** → `x11-access`: if the display accepts clients with no access control (`xhost +`), an `alta` finding with the screen-capture/keylogging commands. **git daemon (9418)** → an exported repo (`--export-all`/`git-daemon-export-ok`) can be **cloned unauthenticated, full history included** (secrets in old commits); commands to try typical repo names.
   - **Every protocol prints concrete next steps** (a ready-to-copy command; e.g. the real `mount` command for an NFS export, or the `no_root_squash` escalation).

   </details>

5b. **Known exploits (`searchsploit`, OFFLINE)** — for every `product`+`version`
    nmap detected, queries the local exploit-db copy (never downloads or runs
    anything). Searches from the most specific term down to the loosest
    (`OpenSSH 8.2p1` → `OpenSSH 8.2`; `Apache httpd 2.4.29` → `Apache
    2.4.29`). Each exploit gets an **estimated severity** (CRITICAL/HIGH/
    MEDIUM/LOW) from a heuristic over its **type** (`remote`→critical if it's
    code execution, `local`/privesc→high, `dos`→low) and title keywords —
    **not an official CVSS score**, just enough to prioritize. Exploits and
    services get sorted by that severity, a service's overall finding
    inherits the worst one, and version-based matching is noisy → **verify
    every `EDB-ID` by hand** with `searchsploit -x EDB-ID`.
5c. **Verified default credentials** — for every service, tries **only**
    known factory/installation credentials and **confirms access** with a
    minimal read operation to **rule out false positives**: it never stops
    at "it connected" — it runs `SELECT 1` (MySQL/PostgreSQL), `PING`
    (Redis), `chassis status` (IPMI), a real *Manager* app load (Tomcat), a
    real *varbind* (SNMP), or `nxc`'s own `[+]`/`(Pwn3d!)` marker. **Short,
    curated per-service list, one attempt per pair, a single target → this
    is NOT brute force** (hydra/medusa with wordlists stays a manual
    suggestion). Covers **FTP, SSH, SMB, WinRM, RDP, LDAP, WMI, VNC** (`nxc`),
    **MySQL** (`mysql`), **PostgreSQL** (`psql`), **MSSQL** (`nxc`), **Redis**
    (`redis-cli`), **SNMP** (community strings, `snmpwalk`), **Oracle**
    (`odat`), **IPMI** (`ipmitool`) and **Tomcat Manager** (stdlib, HTTP
    Basic); **MongoDB** and **Telnet** as suggestions. Passwords go through
    the environment (`MYSQL_PWD`/`PGPASSWORD`/`REDISCLI_AUTH`/
    `IPMI_PASSWORD`), never on the command line. With **`--default-creds`**
    (alias `--creds`) this is the **only** phase that runs (footprinting,
    searchsploit, fuzzing and `--aggressive`'s vuln scripts are skipped; as
    root it adds the usual UDP sweep so it doesn't miss SNMP/IPMI); **`--no-
    creds`** disables it (incompatible with `--default-creds`).
5d. **Provided-credential reuse** — with `--user`/`--pass`, `--user-list`/
    `-U` + `--pass-list`/`-P`, or `--creds-file` (a `user:password` file, one
    per line), reuses the pair(s) against **every** service detected with
    `nxc`. **A valid SMB/LDAP credential doesn't stop at "login OK": palantir
    then enumerates the domain WITH it** (what you actually want from
    `-u/-p/-H`, and what was missing before) — SMB: `--shares` (+ content
    spidering with `--spider`), `--users`/`--pass-pol`/`--rid-brute` (domain
    accounts on a DC, **local** ones on a standalone host — it's SAMR/LSA
    over the SAM either way, no longer gated on being a DC) and
    **`--loggedon-users`** (who has a session open RIGHT NOW on the target —
    needs local admin; tells you where a privileged user is logged in = a
    lateral-movement target) and, if it's a DC, **GPP cpassword** in SYSVOL
    and **noPac** (with this SAME domain account, no admin needed, confirms
    whether the DC lets you impersonate a Domain Admin); LDAP: `--users`/
    `--groups`/`--pass-pol`/`--admin-count`/delegation (and, on a DC, **
    `Domain Admins`/`Enterprise Admins` membership** via `--groups "Domain
    Admins"` — knowing **who** controls the domain focuses the rest of the
    attack), **MachineAccountQuota**, **domain/forest trusts** (via
    `ldapsearch` with a simple bind — `nxc` has no `--trusts` flag, and it
    only works with a plaintext secret, never a hash), **`-M get-desc-
    users`**, **LAPS**, **DCSync-rights**, **adidnsdump**, and the big prize,
    **AS-REP roasting** (`impacket-GetNPUsers ... -request`) and
    **Kerberoasting** (`impacket-GetUserSPNs ... -request`) — both query the
    DC directly for every vulnerable account, no wordlist needed, and dump
    hashcat-ready hashes to a file — and, with `certipy` installed and the
    domain already resolved, `certipy find -vulnerable` (AD CS). With
    **`--hash`/`-H`** it's **pass-the-hash** (an NTLM hash instead of a
    password), applied to the login, the enumeration, and the dump alike —
    it goes literally on the argv while `nxc` runs (its `-H` doesn't support
    the same file trick `-p` does — that's `nxc`'s own interface), but it's
    masked the same way a password is in anything that gets persisted
    (report, `commands.log`): an NTLM hash is just as reusable as a
    plaintext password, it needs no cracking. **`-U`/`-P` cross both lists**
    (every username×password combination) — past a certain size that's
    already real password spraying, not the one-attempt-per-account rest of
    the phase, so against a single target palantir first checks whether
    there's a real lockout policy (`nxc smb --pass-pol` with a null/guest/
    Administrator session) and then asks you to confirm before starting
    (once, not per target). Once a large combo is confirmed, the **list
    brute force runs via `hydra`** for **SSH/FTP/SMB** (quite a bit faster
    than `nxc` and without the `paramiko` bug `nxc` carries over SSH, which
    used to hang the spray until timeout): writes the lists to files and
    calls `hydra` once per protocol (SSH with `-t 4` to avoid connection
    resets). For the **rest** of the protocols, for **pass-the-hash** (`-H`,
    which `hydra` doesn't do), or if `hydra` isn't installed, it falls back
    to `nxc` in bulk (`-u file -p file --continue-on-success`, plus
    `--no-bruteforce` if you asked for it). Two caveats `hydra` needs and
    palantir already handles: for **SMB**, if `hydra` warns "might accept
    any credential" (a Samba that maps any user to guest → everything comes
    back "valid", a false positive) palantir **retries with `nxc`**, which
    does distinguish a real login, and every `hydra` SMB hit gets
    **confirmed with `nxc`** (to know if it's admin and chain the dump); for
    **SSH**, if the server only allows public-key auth, `hydra` says so and
    palantir **reports it** instead of insisting. It doesn't print every
    attempt on screen, just a summary per protocol — the detail stays in
    `commands.log`. **`--no-bruteforce`** turns the N×M cross into N pairs,
    matching line by line (`user[i]` with `password[i]`) — with the **same
    file** passed to `-U` and `-P`, it tries every user with their own name
    as the password. `--creds-file` is explicit pairs instead, never
    crossed, always one `nxc` process per pair (there are few of them, by
    design). The password is masked in the report **and** passed to `nxc`
    via file (never on the subprocess's argv: `ps aux`/`/proc` never see it
    while it runs). Warns about RDP lockout. Combine with `--resume` to
    reuse an existing scan without re-scanning. **If any of these
    credentials returns `(Pwn3d!)` over SMB** (confirmed admin), palantir
    automatically chains `nxc smb --sam` and `--lsa` with that same
    credential — this isn't "try if it works" anymore, it's harvesting
    exactly what that admin session already allows: local-account NTLM
    hashes (blank-password ones flagged separately), DPAPI keys, and, the
    most valuable part, plaintext service credentials stored in LSA. It
    reuses the exact authentication that just earned the Pwn3d! seconds
    earlier (no `--local-auth`), doesn't fire over WinRM/WMI even though
    they imply the same access level (those `nxc` modules are SMB-only), and
    the secrets/hashes the dump **discovers** are shown **in full**
    (masking them would make them useless for pass-the-hash/cracking) — the
    only thing masked is the credential **you** provided to get there in the
    first place (password or `-H` hash, alike). If you need to force
    `--local-auth` (a local account on a target that **is** domain-joined;
    on a standalone Windows box it's not needed, it already validates
    locally by default), pass palantir's own `--local-auth` flag, which
    applies to both the credential check and this dump. **AD CS
    (`certipy`):** with a valid LDAP domain credential **and** the AD domain
    already resolved at that point in the scan, palantir runs `certipy find
    -u user@domain -p/-hashes ... -vulnerable -stdout` — READ-ONLY, writes
    nothing to the AD. If it flags an **ESC1-8** template, a CRITICAL
    finding with `certipy req` (requesting that template's certificate) as a
    **manual** next step: unlike the SAM/LSA dump above (harvesting what an
    already-confirmed admin can see), requesting or forging a certificate
    (`certipy req`/`certipy shadow`) is an **active** escalation — palantir
    never chains it on its own. If the domain **isn't known yet** at this
    point in the scan (the normal case: it resolves later, after the
    footprint), the `certipy find` command is left as a suggestion with the
    domain filled in once it's discovered, instead of running against a
    guessed one. **Databases (MSSQL/MySQL/PostgreSQL):** with a valid
    provided credential, lists databases and, for the non-system ones,
    their tables (read-only); MSSQL additionally covers
    impersonation/linked servers/sysadmin. MySQL/PostgreSQL aren't `nxc`
    protocols (only explicit `--user`/`--pass`/`--creds-file` pairs — the
    `-U`/`-P` list spray isn't supported yet for these two), MSSQL does go
    through `nxc` like the rest. **FEEDBACK LOOP (no loose ends):** once
    phase 5d finishes, every credential palantir has discovered — a valid
    login on ANY service, or a plaintext credential / NTLM hash dumped from
    SAM/LSA — gets **retried against the rest of the detected services**
    and, if it opens a new one over SMB/LDAP, gets enumerated with it (which
    can surface even more credentials → feeding back into the loop).
    Bounded: 3 rounds, 20 credentials, **one attempt per pair and protocol**
    (never a spray → no lockout risk beyond 1/account/protocol),
    deduplicated. So a password found over SSH also gets tried over
    SMB/LDAP, and a service credential dumped from LSA gets tried against
    every service — without you having to reuse it by hand.
6. **Web fuzzing (ffuf)** — directories/files with **extensions guessed from
   the server** (IIS→`asp,aspx,...`; PHP→`php`; Tomcat→`jsp`; Apache→`cgi,
   php`). `-ac -ic -maxtime`. Wordlists via `--profile` or `-w`. If the
   target has **several web ports**, they're fuzzed **in parallel** (up to 4
   at once; ffuf runs in silent mode, so it doesn't flood the screen); under
   `--stealth` or with a single port, one at a time.
7. **Vhost / subdomains** — `ffuf -H "Host: FUZZ.domain" -ac`. The
   **domain is auto-discovered** from certificates/redirects/enumerated
   SMB; can be forced with `--vhost`. If phase 5 pulled subdomains from
   `crt.sh` for that domain, they're confirmed **first** (a tiny wordlist,
   already known from a certificate) before the big dictionary. With
   **`--vhost-names LIST`** (vhosts you already know — the lab statement
   hands them to you, e.g. CPTS's "Virtual Hosts") it skips the whole
   dictionary fuzz and goes straight to confirming. **Any confirmed vhost**
   (by dictionary, by `crt.sh`, or by `--vhost-names`) gets **automatically
   fingerprinted** separately with `whatweb --header "Host: <vhost>"` —
   without this, phase 5's `whatweb` only ever sees the server's **default**
   vhost, never the others (which can run a completely different
   Apache/CMS/OS). Against a **pure catch-all** (the server answers the
   same to any `Host`, and `-ac` filters EVERYTHING), it measures the
   wildcard's response size and retries with `-fs <len>` to recover the real
   vhosts.
7b. **Per-vhost directory fuzzing** — for every confirmed vhost, its
    **directory tree** also gets fuzzed, sending `Host: <vhost>` as a header
    against the IP (doesn't depend on DNS), because each vhost can serve
    different content that phase 7's (default-vhost) fuzzing never sees.
    Capped at a **maximum of 6 vhosts**: beyond that, it's skipped entirely
    (none of them get fuzzed) to avoid runaway runs.
8. **Reports** — besides the on-screen ANSI output, now **boxed** by
   context, all at the **same width** (they line up, nothing "jumps around"):
   every **phase header** gets its own single-line box (cyan) with the *why*
   inside; the **★ Quick wins** box (double-lined, red) at the end gathers
   the most actionable findings — valid credentials, RCE, readable shares,
   AXFR... — with the exact command (long ones wrap inside the frame
   instead of getting cut off) and, for the most common categories, a
   **💡 tip** underneath (what approach to follow BY HAND — never a new
   command, just reasoning text: see [Safe for exam use](#safe-for-exam-use)
   below); and the **final per-target summary** gets a box with a
   gradient border (`RESUMEN · <ip>`: total time, number of ports/protocols,
   finding counts by severity, the single most critical "start here" item
   with its command and tip if any, and the `report.html` path — everything
   you need at a glance, without scrolling back up after a long scan):
   - **PRELIMINARY report (before fuzzing)** — as soon as scanning,
     footprinting and searchsploit finish, and **before** web/vhost fuzzing
     (the longest phase) starts, `report.html`/`report.md`/`findings.json`
     already get written with everything found so far. The preliminary HTML
     carries a banner and **auto-refreshes every 60s**, and **keeps
     growing** with every port/vhost fuzzing finds; the final report (no
     banner) replaces it once everything's done. That final report is
     **always** written, even if you `Ctrl-C` or a fuzzing command fails —
     you never end up without a report.
   - **`report.html`** — a self-contained report (no CDNs), dark amber
     theme, with **Quick wins** up top, a **"Jump to:"** index into every
     section (opens the target `<details>` and scrolls to it), **native
     `<details>` collapsibles** grouped by **real protocol** (the anonymous
     footprint + default credentials (phase 5c) + provided credentials
     (phase 5d) for the SAME protocol live in one collapsible, with
     sub-sections), summary cards, **findings sorted by severity**
     (critical/high/medium/info color-coded) with a **per-severity count
     strip** right under the heading (N critical · N high · N medium · ...),
     a **copy button** on every command, a text filter, and
     expand/collapse-all buttons. Attempts with **zero success** (a null
     session/default credential that opened nothing) collapse under an "N
     attempts tried, none successful" — nothing gets deleted, it just stops
     taking up screen space when it found nothing; anything that DID find
     something is always shown in full, expanded. The known AD domain shows
     up in the header and auto-fills the commands that need it (AS-REP
     roast/Kerberoasting/`impacket-wmiexec`), same for the DC's NetBIOS
     name in the Zerologon exploit — no `DOMAIN`/`DC-NETBIOS` placeholders
     left for you to fill in by hand once palantir already knows them. The
     suggested impacket scripts (`GetNPUsers`/`GetUserSPNs`) use whatever
     name you actually have installed: `impacket-GetNPUsers` (the
     `impacket-scripts` apt package, the Kali default) or bare `GetNPUsers`
     (the `pip install impacket` entry point), falling back to
     `GetNPUsers.py` only if neither is detected.
   - **`report.md`** — the same report in **Markdown** (Quick wins +
     findings + ports + footprint + exploits + web), grouped by protocol
     just like the HTML, ready to paste straight into CPTS notes/writeups.
   - **`findings.json`** — the full result as machine-readable JSON (ports,
     NSE scripts, footprints, findings, domains, web; with
     `"preliminary": true/false`) for reprocessing or feeding into a pentest
     report.

## Requirements

- **Core:** `python3` and **nmap** (required). Everything else is optional
  and auto-detected at runtime.
- **Recommended on Kali:** `ffuf` + `seclists` (web/vhost), `exploitdb`
  (`searchsploit`), `netexec` (`nxc`: SMB/LDAP/WinRM/RDP/VNC/WMI/MSSQL/
  NFS/SSH/FTP), `smbclient`/`rpcclient`/`smbmap`/`enum4linux-ng` (SMB),
  `impacket-scripts` (`impacket-rpcdump`, `GetNPUsers`/`GetUserSPNs`),
  `nfs-common` (`showmount`), `dnsutils` (`dig`), `whois`, `ldap-utils`
  (`ldapsearch`), `whatweb`, `wafw00f` (WAF detection), `snmp`/`onesixtyone`
  (SNMP), `tnscmd10g`, `redis-tools` (`redis-cli`). For **verified default
  credentials** (phase 5c), also: `default-mysql-client`/`mariadb-client`
  (`mysql`), `postgresql-client` (`psql`), `odat` (Oracle), `ipmitool`
  (IPMI) and, for MongoDB, `mongosh` (**not in apt** — the official MongoDB
  repo; manual install, `--install-missing` doesn't cover it). Optional for
  less common protocols: `rusers`/`rstat-client` (R-Services) and `rsync`.
  On Kali most of this ships by default; `nxc` is the key piece for
  Windows/AD footprinting.
- **Opt-in web tools** (only run if you pass their flag; skipped gracefully
  if absent): `nikto` (`--nikto`, apt: `nikto`), `wpscan` (`--cms-scan` on
  WordPress, apt: `wpscan`), `joomscan` (`--cms-scan` on Joomla — **not in
  apt**: [github.com/OWASP/joomscan](https://github.com/OWASP/joomscan)),
  `katana` (`--crawl`, apt: `katana`) and `nuclei` (`--nuclei`, apt:
  `nuclei`). **`nuclei`** downloads its templates on the **first run**
  (needs internet once; or `nuclei -update-templates` by hand); once
  they're on disk, palantir adds `-duc` so it doesn't re-validate them on
  every run. No API key needed.
- **`crt.sh`** (Certificate Transparency, phase 5): **NOT an apt package** —
  it's the [az7rb/crt.sh](https://github.com/az7rb/crt.sh) CLI, installed
  via Go (`go install github.com/az7rb/crt.sh@latest`), ending up in
  `$HOME/go/bin` or wherever `$GOPATH` points. Under `sudo`, palantir
  already knows to look for it outside root's restricted PATH (tries the
  real user's `$HOME/go/bin` and `/opt/go/bin`). `--install-missing`
  installs it without needing Go: it downloads the precompiled binary from
  the latest GitHub release.
- **`certipy`** (AD CS, phase 5d): **NOT an apt package** — installed via
  pip/pipx (`pipx install certipy-ad`), same as `nxc` ends up in
  `$HOME/.local/bin`. Under `sudo`, palantir already knows to look outside
  root's restricted PATH. `--install-missing` installs it on its own (pipx
  if present, else `pip install --user`).
- **`adidnsdump`** (internal DNS over LDAP, phase 5d): also not an apt
  package — `pip install adidnsdump` (same case as `certipy`, same PATH
  handling under `sudo`; `--install-missing` installs it the same way as
  `certipy`). `impacket-secretsdump` (DCSync-rights) **does** ship in apt,
  in the same `impacket-scripts` package that already brings
  `impacket-rpcdump`.
- **`kerbrute`** (Kerberos user enum, phase 5): **NOT an apt package** —
  the [ropnop/kerbrute](https://github.com/ropnop/kerbrute) Go binary;
  usually ends up in `$HOME/go/bin`, `/usr/local/bin` or `~/.local/bin`.
  Under `sudo`, palantir looks outside root's restricted PATH.
  `--install-missing` downloads it on its own (precompiled binary from the
  latest GitHub release, no Go toolchain needed). For automatic userenum,
  having **seclists** helps (it uses its `top-usernames-shortlist.txt` if
  nothing better is available; `--install-missing` installs that too, it's
  an apt package) and, above all, **`jsmith.txt`**
  ([insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) —
  NOT bundled in seclists). With `--install-missing`, palantir downloads it
  on its own to `/usr/share/wordlists/statistically-likely-usernames/jsmith.txt`;
  by hand it would be:
  ```bash
  mkdir -p /usr/share/wordlists/statistically-likely-usernames
  curl -o /usr/share/wordlists/statistically-likely-usernames/jsmith.txt \
    https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/jsmith.txt
  ```
  With jsmith.txt at that path (either way), palantir uses it automatically
  (no need to pass `--userenum-wordlist`) — see the Kerberos row in
  [What it does](#what-it-does).
- Run as **root** for SYN scan (`-sS`) and UDP; without root it falls back
  to connect scan (`-sT`).

## Usage

```bash
chmod +x palantir.py

# Full recon by default (recommended with sudo): scan + vuln scripts +
# deep footprint + default creds + searchsploit + fuzzing + UDP (if root) + HTML
sudo ./palantir.py 10.129.21.27

# Faster/quieter: no vuln scripts, no deep footprint, no UDP
sudo ./palantir.py 10.129.21.27 --no-aggressive --no-udp

# Big wordlist profile + vhost/AXFR for a known domain
sudo ./palantir.py 10.129.21.27 --profile big --vhost inlanefreight.htb

# Scan + footprint only, no fuzzing or reports
./palantir.py 10.129.21.27 --no-fuzz --no-html

# ONLY verified default credentials, every service
sudo ./palantir.py 10.129.21.27 --default-creds

# Multi-target: CIDR, range, list or file (+ add hosts to /etc/hosts without asking)
sudo ./palantir.py 10.129.21.0/24 --add-hosts
sudo ./palantir.py "10.129.21.27, 10.129.21.40, target.htb" --top
sudo ./palantir.py --targets targets.txt

# Several targets IN PARALLEL (e.g. a /24, 4 at a time; [ip]-tagged output)
sudo ./palantir.py 10.129.21.0/24 --jobs 4

# Stealth lab: slow/fragmented nmap + delayed ffuf, through Burp
sudo ./palantir.py 10.129.21.27 --stealth --proxy http://127.0.0.1:8080

# Firewall that trusts a specific port (e.g. 53/DNS)
sudo ./palantir.py 172.16.119.7 --tunnel   # through a pivot (ligolo-ng/chisel/SOCKS): doesn't lose ports
sudo ./palantir.py 10.129.21.27 --source-port 53

# Known port (HTB Academy "Virtual Hosts" lab: skip sweeping all 65535 ports)
sudo ./palantir.py 10.129.21.27 --port 38490 --vhost inlanefreight.htb

# Already-known vhosts (the lab gives you the names): straight to fingerprinting
sudo ./palantir.py 10.129.21.27 --vhost-names app.inlanefreight.local,dev.inlanefreight.local

# Reuse a credential against EVERY service (phase 5d), without rescanning
sudo ./palantir.py 10.129.21.27 --resume --user svc_admin --pass Passw0rd!
sudo ./palantir.py 10.129.21.27 --resume -U users.txt -P passwords.txt   # crosses both lists (real spraying)

# Valid domain credential: enumerate WITH it (shares/users/groups/kerberoasting) + content spidering
sudo ./palantir.py 10.129.234.121 --resume -u mendres -p 'Inlanefreight2025!' --spider
# Pass-the-hash with an NTLM hash (no password)
sudo ./palantir.py 10.129.21.27 --resume -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 --local-auth

# Internal test of the parsers and HTML generator (no network)
./palantir.py --selftest
```

## Flags

| Flag | What it does |
|---|---|
| `target` | IP, CIDR (`10.10.10.0/24`), range (`10.10.10.1-20`), hostname, or several separated by comma/space. |
| `--targets FILE` | File with targets (one per line; `#` comments). |
| `--add-hosts` / `--no-add-hosts` | Add (without asking / never) discovered domains to `/etc/hosts`. Asks by default. |
| `--top` | Top-1000 ports only in phase 1 (faster). |
| `--no-sweep` | Disables **phase 0** (the `nmap -sn` ping sweep over CIDRs/ranges that prunes dead hosts before sweeping them one by one). Use it if targets block ICMP. **ON by default except under `--tunnel`**, where it disables itself (see `--tunnel`). |
| `--aggressive` / `--no-aggressive` | A 2nd nmap run with `vuln`/backdoor scripts **and** deep footprinting (`enum4linux-ng`, `onesixtyone`). **ON by default**; `--no-aggressive` disables it (faster/quieter). |
| `--udp` / `--no-udp` | UDP sweep of the key ports (SNMP, IPMI...). **ON by default as root**; `--no-udp` disables it. |
| `--stealth` | nmap `-T2 -f`; ffuf with fewer threads, a delay, and a normal UA. Much slower. |
| `--proxy URL` | Proxy for ffuf (`http://host:port` or `socks5://host:port`). |
| `--source-port PORT` | Source port for nmap and the manual banner grabbing (port-based evasion like `53`/DNS). |
| `--tcp-connect` (`--connect`) | Forces connect scan (nmap `-sT`) even as root, instead of the default SYN (`-sS`). For WSL2 mirrored networking + a VPN, where raw SYN packets get dropped in the tunnel (nmap sees "host up" with 0 ports). Without this, palantir already retries with `-sT` on its own if the SYN scan finds nothing. |
| `--tunnel` (`--pivoting`, `--pivot`) | Tunes the scan for **pivoting/tunneling** (ligolo-ng, chisel, sshuttle, `ssh -D`, SOCKS/proxychains, Meterpreter, WSL2+VPN...). Forces `-sT`, **drops `--min-rate`** (its fixed pace floods the relay's userland TCP stack → nmap marks **open** ports as `filtered`) and uses **`--max-retries 10`** (nmap's own default; lowering it to 3 was the first version's bug); `-T3` in phases 1/2; drops banner grabbing to 4 threads (from 16) so it doesn't flood the relay. **Keeps the full `-p-` sweep** (through a tunnel it takes several minutes but doesn't lose ports, not even a DC's high dynamic RPC ports, 49xxx); with `--top` you get just the fast top-1000. **Doesn't route anything by itself**: for a route-based pivot (ligolo/sshuttle) you run palantir normally, for a SOCKS one (chisel/`ssh -D`) you wrap it in `proxychains`. **Disables phase 0 (ping sweep) on its own** and warns about `--source-port` (doesn't survive a SOCKS hop). See [Pivoting / tunneling](#pivoting--tunneling) for the full breakdown by tunnel type and measured timings. |
| `--resume` | Reuses existing nmap XML (doesn't rescan) AND, if ports/services didn't change, the previous footprint/searchsploit/default-creds results from `findings.json` too (not repeated): only reruns fuzzing/reports and, crucially, any newly provided credentials (`-u/-p/-H/-U/-P`), which are never skipped. Useful for iterating on the same box. |
| `--profile quick\|medium\|big` | Wordlist set (default `medium`; `big` uses several). |
| `-w L [L ...]` | Explicit wordlists (overrides `--profile`). |
| `--no-big-wordlist` | Don't add `dirb/big.txt` (~20k lines) on top of whatever `--profile`/`-w` picked — it's otherwise always added regardless of profile. For real (non-lab) targets where every extra port multiplies the time. |
| `--ext .php,.txt` | Force extensions (otherwise guessed from the server). |
| `--vhost DOMAIN` | Forces vhost fuzzing **and** DNS AXFR/WHOIS/crt.sh (otherwise the domain is auto-discovered). No effect on phase 7 if you also pass `--vhost-names` (only still used for AXFR/WHOIS). |
| `--vhost-names LIST` | Vhosts you ALREADY KNOW, comma-separated (e.g. `app.x.local,dev.x.local`). Skips phase 7's dictionary fuzzing and goes straight to confirming/fingerprinting each one. |
| `--vhost-wordlist FILE` | Subdomain wordlist for vhost fuzzing (default: seclists' subdomain list). |
| `--no-vhost-fuzz` | Skips ONLY phase 7 (guessing subdomains by dictionary); keeps phase 6 (directory fuzzing). For bug-bounty scopes where hostnames are explicitly listed and the rest of the subdomains (`*.domain.com`) are out of scope. |
| `--port PORTS` | Restricts the ENTIRE scan to these ports (comma-separated: `80,443,38490`) instead of `-p-`/`--top-ports` — for when you already know the port (e.g. HTB Academy labs). Ignores `--top`. No short alias on purpose (not to be confused with `--pass`'s `-p`). |
| `--snmp-wordlist FILE` | Community-string wordlist for the SNMP brute force with `onesixtyone` (only with `--aggressive`; default: seclists'). |
| `--userenum-wordlist FILE` | Username wordlist for phase 5's `kerbrute userenum` (AD user enum over Kerberos pre-auth; **never locks accounts**). Without this, on a DC with a known domain it automatically uses `jsmith.txt` if installed (realistic employee names, minutes — see Requirements above) or otherwise a **small** seclists list (seconds); give it a big one (e.g. xato-10M) for a thorough sweep (it'll take a while, up to 2h). |
| `--no-userenum` | Don't run phase 5's automatic `kerbrute userenum` (leaves it as a suggestion only). |
| `--spray PASS` | **Automatic password spraying** against the AD users palantir discovers **live** (`kerbrute userenum` + SMB/LDAP enum → `ad_users.txt`): sprays **this** password against all of them with `kerbrute passwordspray --safe`. **No `-u` needed** — palantir finds the users on its own. Several passwords, comma-separated. Only against a **DC with a resolved domain**. An **active** step: a failed pre-auth counts as a failed login and **can lock accounts** — `--safe` aborts as soon as it detects a lockout, and palantir warns beforehand. The password is **masked** in the report; `user:pass` hits only show on screen. A hit is a **critical** finding with next steps to reuse the credential. |
| `--min-rate N` | Minimum nmap packets/second (default `5000`). Higher = faster and noisier. **Ignored with `--tunnel`** (there, a fixed rate is exactly what loses ports through the pivot). |
| `--jobs N` / `-j` | Targets to scan **in parallel** (default `1` = sequential). For a `/24` or a large list. Each target in its own thread, with its own `report.html`/`commands.log`, `[ip]`-tagged lines, no interactive prompts. Live nmap/ffuf output from several targets interleaves. **Don't combine with `--tunnel`** (it saturates the shared tunnel → you lose ports; palantir warns). |
| `--user USER` / `-u` | Phase 5d: username to reuse against every `nxc`-detected service. Combines with `--pass` (or with `--pass-list`/`-P`). |
| `--pass PASS` / `-p` | Phase 5d: password for `--user` (omit it to try an empty one). |
| `--hash NTLM` / `-H` | Phase 5d: **pass-the-hash** — an NTLM hash (`NTHASH` or `LMHASH:NTHASH`) instead of a password (`nxc -H`). Used with `--user`/`-u` (or `--user-list`/`-U`) against every NTLM service (SMB/WinRM/RDP/WMI/MSSQL/LDAP); with `--local-auth` for a local account. A valid credential enumerates the domain just like `--pass` does. Incompatible with `--pass`/`--pass-list`/`--creds-file`. |
| `--user-list FILE` / `-U` | Phase 5d: a file with one username per line (`#` comments). With `--pass-list`/`-P` at the same time, **crosses** both lists (every combination) — that's already real spraying, not the one-attempt-per-account rest of phase 5d; with large lists it checks the lockout policy if it can and asks you to confirm. |
| `--pass-list FILE` / `-P` | Phase 5d: a file with one password per line (`#` comments). See `--user-list`. |
| `--no-bruteforce` | With both `-U` **and** `-P`: pairs them line by line instead of crossing — N pairs instead of N×M. `-U list.txt -P list.txt --no-bruteforce` tries every user with their own name as the password. |
| `--creds-file FILE` | Phase 5d: a `user:password` file (one per line, `#` comments) — explicit pairs, **never** crossed. Combine with `--resume`. |
| `--spider` | SMB: **content** spidering of readable shares via `nxc` (`--spider SHARE --content`): looks for secrets **inside** files, not just by filename. Uses the provided credential (`-u/-p/-H`) if given, or whatever anonymous session got in. Slow on large shares — opt-in. |
| `--pattern PATTERN` | Pattern(s) for `--spider` (`nxc --pattern`), comma-separated. If not given, `--spider` searches a default secrets regex (`passw`/`secret`/`cred`/keys). Passing `--pattern` implies `--spider`. |
| `--local-auth` | Phase 5d: adds `--local-auth` to `nxc` (SMB/WinRM/RDP/WMI/MSSQL/LDAP; **not** SSH/FTP/VNC, which don't have that distinction). Needed when the target **is** domain-joined but the credential you're testing is a **local** account on that machine — without it, `nxc` validates it against the domain and it fails even if it's valid locally. On a **standalone** Windows box (no domain) it's not needed: it already validates against the local SAM by default. Also applies to the automatic SAM/LSA dump. |
| `--default-creds` (`--creds`) | **Only** verified default credentials across every service; skips footprinting, searchsploit, fuzzing and `--aggressive`'s vuln scripts. Incompatible with `--no-creds`. |
| `--no-creds` | Don't try default credentials (skips phase 5c). |
| `--install-missing` | Installs whatever's missing without asking: `apt` for what's in the repos, and automatically for what isn't (pip/pipx, or downloading a binary/file from GitHub — jsmith.txt, kerbrute, certipy, adidnsdump, crt.sh), always naming what's about to be downloaded and from where before doing it. `mongosh`/`joomscan` stay manual-install instructions (too environment-dependent to automate with confidence). **With no target**, it acts as an installer: checks everything, installs, and exits. |
| `--check-tools` | Only lists what's missing and how to install it (apt / automatic download / manual) — doesn't install, doesn't scan — and exits. Takes priority over `--install-missing` if you pass both. |
| `--no-preflight` | Skip the startup check for missing tools (continues straight away). |
| `--nikto` | Actually runs `nikto` against every web service (phase 5), not just suggests it. OFF by default: slow (several minutes per service) and noisy. |
| `--cms-scan` | If `whatweb` detected WordPress/Joomla, runs `wpscan`/`joomscan` (plugins/themes/users/vulns). OFF by default: just as slow/noisy as `--nikto`. |
| `--crawl` | Real crawling with `katana`: real links/JS/forms (not guessed). Capped (`-d 2`, max 60 pages). OFF by default. |
| `--nuclei` | Runs `nuclei` (ProjectDiscovery) against every web service: CVE/exposure/misconfig templates, filtered to `low+` severity. OFF by default: a full template scan is slow/noisy — opt-in. **Templates:** auto-downloaded the first time (needs internet; or `nuclei -update-templates` by hand); once on disk, palantir adds `-duc` to skip the update check on every run (no network needed). If it runs with no templates, it warns with the fix. No API key needed. |
| `--no-scripts` / `--no-banner` / `--no-footprint` / `--no-searchsploit` / `--no-fuzz` / `--no-html` | Skip that phase. |
| `-o DIR` / `--outdir DIR` | Base output folder (default `~/htb`). |
| `--selftest` | Runs the internal test suite (parsers + HTML/Markdown generator, no network) and exits. |

## Pivoting / tunneling

**Stealth mode** (`--stealth`, for evasion-focused labs) — nmap gets more
cautious (`-T2` instead of `-T4 --min-rate`, more fragmentation): the port
sweep (phase 1) runs `-T2 -f --data-length 24`, enumeration (phase 2) runs
`-T2` and `-f` **only as root** (with `-sT` and no root, `-f` would make
nmap abort), and UDP (phase 3) runs `-T2`. ffuf drops to 5 threads, adds a
0.5-1.5s delay between requests and swaps its default User-Agent (a
recognizable signature in logs/WAFs) for a regular browser one. Everything
is deliberately much slower. `--proxy http://host:port` routes ffuf through
a proxy (Burp, SOCKS...), with or without `--stealth`.

**Pivoting / tunnel mode** (`--tunnel`, alias `--pivoting`/`--pivot`) — for
scanning through a pivot (ligolo-ng, chisel, SOCKS, Meterpreter, WSL2+VPN...).
Through a tunnel the TCP stack runs in userland and saturates easily: the
default `-T4 --min-rate 5000` **floods the relay**, and nmap marks as
`filtered` ports that are actually **open** but whose responses got lost in
the tunnel (a real case: a direct `nmap -sT` found both 3389 **and**
5985/WinRM, but palantir only saw 3389 — 5985 got lost). `--tunnel` forces
connect scan (`-sT`) and changes the timing: **drops `--min-rate`** (without
that fixed floor, nmap's own congestion control slows down on its own the
moment it detects loss — exactly what the fixed `--min-rate` used to
prevent) and uses **`--max-retries 10`** (nmap's default, the one that
actually recovers those probes — the plain `nmap -sT` that DID find 5985
used it; dropping it to 3, like the flag's first version did, was exactly
the wrong move). **Keeps the full `-p-` sweep**: confirmed live that
`nmap -sT -p-` over ligolo-ng finds both 3389 **and** 5985, including a
DC's high dynamic RPC ports (49xxx) that a top-1000 scan would miss. If you
just want the usual ports fast, add **`--top`** (top-1000, includes 5985).
Much faster than `--stealth`. UDP over a tunnel is generally unreliable
(many relays don't even pass it through). Put it in `~/.palantirrc` if you
always pivot. **Don't combine it with `--jobs >1`**: the tunnel is a shared
bottleneck, and scanning several targets through it at once saturates it
(nmap's congestion control is per-process, it doesn't coordinate across
threads) → you lose ports again, exactly what `--tunnel` exists to avoid.
Through a pivot, use `--jobs 1` (sequential); palantir warns if you combine
both.

**`--tunnel` ONLY tunes the scan, it does NOT route anything.** How your
traffic actually reaches the target depends on the tunnel's **type**, and
that changes what works and what doesn't:

- **Route-based** (ligolo-ng, sshuttle, WSL2+VPN): the pivot puts the target
  network into your **routing table** (ligolo-ng creates an **L3 TUN**
  interface; sshuttle does **transparent NAT** via iptables). You run
  `palantir ... --tunnel` **normally** and the OS routes EVERYTHING through
  the pivot: nmap, the banner grabbing, `nxc`, `ffuf`, all of it. No need
  for `proxychains`.
- **SOCKS-based** (chisel `socks`, `ssh -D`, Meterpreter `socks`): the pivot
  only opens a local **SOCKS port** (e.g. `127.0.0.1:1080`). For palantir to
  use it you have to **wrap the whole thing**: `proxychains palantir ...
  --tunnel`. `proxychains` intercepts libc's `connect()` (its `LD_PRELOAD`
  is inherited by every child process: nmap, Python, nxc...), **but only
  TCP via `connect()`** — nmap's raw-socket scans (SYN, UDP, ICMP) **bypass
  it** and either fail or get filtered, which is why `--tunnel` forces
  `-sT`. If you DON'T wrap it with `proxychains`, only `ffuf` (with
  `--proxy socks5://127.0.0.1:1080`) would go through the pivot; everything
  else would go out your direct interface and never reach the target.

What survives each tunnel type:

| | ligolo-ng (L3 TUN) | sshuttle (NAT) | chisel/ssh -D/proxychains (SOCKS) |
|---|---|---|---|
| **How you run palantir** | normally (there's a route) | normally (there's a route) | `proxychains palantir ...` |
| **`-sT` connect scan** | ✅ (the only one that makes sense) | ✅ | ✅ |
| **SYN `-sS` / stealth** | ❌ (the agent runs unprivileged → it ends up being a `connect()` anyway, no stealth) | ❌ | ❌ |
| **Ping sweep `-sn` (phase 0)** | ⚠️ may run but gives **false positives** (known invalid-ACK bug) | ❌ no ICMP | ❌ ICMP doesn't cross SOCKS |
| **UDP (`--udp`)** | ⚠️ sometimes (the agent relays the datagram) | ❌ DNS only | ❌ SOCKS almost never does UDP-ASSOCIATE |
| **`--source-port`** | ✅ (a real packet leaves from your host) | ❌ NAT rewrites the source | ❌ decided by the proxy, not nmap |

That's why `--tunnel` **disables phase 0 on its own** (on a CIDR, an `-sn`
that reports "everyone's dead" would abort the whole run before it actually
scans anything) and **warns** if you combine `--source-port` (it doesn't
survive a SOCKS hop). An `ssh -L` (forwarding **one** port) isn't a general
scanning path: point palantir at that port with `--port` instead.

**How long it takes.** Through a tunnel, `-sT -p- --max-retries 10` with no
`--min-rate` is **deliberately slow** (not flooding the relay = not losing
ports). Measured live: **~6-7 min for phase 1** (`-p-`, 65535 ports) against
ONE host over ligolo-ng; over a SOCKS/proxychains setup it's even slower
(every `connect()` pays the pivot's RTT). The rest of the phases run over
the few ports already found, so they're fast. If you don't need all 65535
ports: **`--top`** (top-1000, ~1 min, includes 5985) or **`--port N`** if
you already know which one. `--tunnel` also drops banner grabbing to 4
threads (from 16) so it doesn't flood the relay.

**Source port** (`--source-port PORT`) — for firewalls that trust a
specific port (the classic one is 53/DNS). Applies to both the nmap scans
**and** the manual banner grabbing: the trick doesn't just need the scan to
use that port, the real connection used to grab the banner has to leave
from it too, same as `nc -p 53`/`ncat --source-port 53`. Ports <1024 need
root.

**Several targets in parallel** (`--jobs N`) — by default targets are
scanned one at a time; with `--jobs N` up to N run at once (useful for a
`/24` or a large list). Each target runs in its own thread, with its own
`report.html`/`commands.log`, and its output lines get tagged `[ip]`; with
`--jobs>1` there are no interactive prompts (the `/etc/hosts` suggestion is
just left for you to add by hand). Live nmap/ffuf output from several
targets interleaves — for a calm review of each one, use its report.
With more than one target in the run (either via `--jobs N` or a
`--targets` file with several lines), an extra **`<outdir>/index.html`**
gets written: a table linking to each target's `report.html`, its
ports/findings by severity, and whether any of them failed (with its
`error.log` handy) — so you don't have to open folder after folder for
several machines. Each row shows the IP and, in parentheses, the
**hostname** if it was given via `--targets`/CLI or if the scan itself
discovered it (SMB/LDAP/DNS/certificate) — you don't have to have passed
it by hand.

Also: a sorted ANSI table, a **★ highlighted findings** block, a
per-protocol footprinting summary with ✓/· per command, a suggested
`/etc/hosts` line, and everything saved under `~/htb/<ip>/` (`nmap/` with
`-oA`, `web/` with ffuf's JSON output, `report.html`, `report.md`,
`findings.json`, `commands.log` and, if a target fails, `error.log` with
the traceback).

## Notes

- Every target is resolved/validated (IP, CIDR, range or hostname) before
  being handed to nmap (avoids traversal/option injection). The list gets
  **deduplicated by `(ip, name)`**, not by bare IP: two different hostnames
  that resolve to the same IP (e.g. behind a CDN) are **both** scanned.
  **Multi-target**: by default **sequential** (one at a time, clean output
  and prompts); with **`--jobs N`**, up to N **in parallel** (one thread per
  target, `[ip]`-tagged output, no prompts). Results normally go to
  `<outdir>/<ip>/`; if **several targets in the same run share an IP** (the
  case above), the named ones get namespaced to `<outdir>/<ip>_<hostname>/`
  so they don't clobber each other — the normal case (one target per IP)
  still uses plain `<outdir>/<ip>/`. **The real folder never gets renamed**
  (that would break `--resume`): as soon as its own hostname is discovered
  (e.g. `file01.nexura.htb`), palantir additionally creates a **convenience
  symlink** `<outdir>/<hostname> -> <outdir>/<ip>/` so you can `cd` by name
  if you prefer — never for the bare base domain (`nexura.htb`), which
  every box in the same AD domain shares and would clobber.
- **Tool check (pre-flight):** before touching the target, if tools
  **needed by your flags** are missing, it warns once (listing what would
  be skipped, and WHERE each one would be installed/downloaded from) and
  lets you choose: **[i]nstall**, **[c]ontinue** without them (those
  services just get skipped, the rest of the scan runs the same), or
  **[a]bort**. In a non-interactive shell it continues without asking.
  `--install-missing` installs without asking; `--no-preflight` skips the
  whole check. `[i]nstall` covers two paths: `apt` for what's in the repos
  (nmap, nxc, seclists...), and automatic download/install for what isn't —
  `pip`/`pipx` (certipy, creds, adidnsdump) or a precompiled binary/file
  from the latest GitHub release (kerbrute, crt.sh, jsmith.txt) — always
  showing the exact source (URL or package) BEFORE asking, never after. If
  a download fails (or even raises an exception), it warns with the reason
  and the rest of the check continues the same — it never crashes the scan.
  Whatever isn't automated with confidence stays manual instructions, same
  as before: `joomscan` (Perl/cpan dependencies too different across
  distros) and `mongosh` (installing via npm would need sudo without
  privilege, but under sudo root's restricted PATH probably doesn't see an
  npm installed via nvm — and even if it installed fine, nothing in the
  file knows how to find it afterward: unlike certipy/kerbrute, `mongosh`
  has no resolver with a `.local/bin` fallback).
- **Does everything recommended by default:** just `sudo ./palantir.py <ip>`
  already runs scan + vuln scripts + deep footprint + **default
  credentials (phase 5c)** + searchsploit + fuzzing + UDP (if root). It
  prints the *active phases* on startup. To go lighter, disable with
  `--no-aggressive`, `--no-udp`, `--no-creds`, `--no-fuzz`, etc.
  `--default-creds` does the opposite: ONLY default credentials.
- Footprinting is **read-only and default-credentials-only**
  (anonymous/null/guest/`Administrator`/`sa`, all with no password): **a
  single attempt per account** to catch misconfigurations — not brute
  force, not password spraying, and never a write to the target. Validating
  username/password lists always stays a **manual suggestion** in the
  report, never executed. The **one deliberate exception** is
  `--user-list`/`-U` + `--pass-list`/`-P` together (phase 5d): that really
  does cross both lists — you ask for it explicitly, with your own files,
  and with large lists palantir warns about lockout risk and asks you to
  confirm before starting. The **other** one is the automatic SAM/LSA dump
  (also phase 5d): it only fires once a credential **you** provided
  (`--user`/`-U`/`--creds-file`) returns `(Pwn3d!)` over SMB — it's not a
  new attempt against the target, it's using the admin access that was
  already demonstrated seconds earlier to extract what that same admin
  session already allows seeing (equivalent to running
  `secretsdump.py`/crackmapexec by hand). Use only against authorized
  targets (HTB/CPTS labs, engagements with permission).
- **Phase 2 can "lose" a port phase 1 found open** — they're two separate
  nmap runs, and phase 2 **replaces** phase 1's port list, it doesn't merge
  with it: if the target flaps between the two (rate limiting after two
  back-to-back 65535-port sweeps, a stateful firewall...) and a port no
  longer shows "open" on the re-scan, it silently drops out of the rest of
  the recon. If this happens, palantir explicitly warns which port(s)
  disappeared and why, with the command to check by hand — **`--resume`
  won't help here**, it would just reuse that same already-"filtered" XML.
- **Educational mode:** every command is printed with its *why* (a
  `↳ why:` line on screen and in the HTML), so the report doubles as a
  learning aid for why each thing runs.
- **`~/.palantirrc` config:** if it exists, its lines are treated as
  default flags (one or more per line, `#` comments) and get prepended to
  the CLI ones → the command line always wins. Under `sudo` it reads the
  real user's file. Example: a line with `--profile big --no-udp` and you
  always scan with that profile without repeating it.
- **`--resume`:** reuses the `*.xml` files already in
  `<outdir>/<ip>/nmap/` instead of rescanning (if the XML isn't there, it
  scans normally). **On top of that**, if the detected ports/services are
  EXACTLY the same as in the previous run's `findings.json` (and no nmap
  run had to actually rescan), it **doesn't repeat** footprinting (phase 5,
  incl. `whois`/`crt.sh`)/searchsploit (5b)/default credentials (5c) —
  reuses them from the previous run and says so on screen. **Provided
  credentials** (phase 5d, `-u/-p/-H/-U/-P`) are the exception: they never
  get skipped, they're exactly what you usually want to re-run with
  `--resume` after finding a new credential. If you changed flags that
  affect the footprint (`--nikto`/`--nuclei`/`--cms-scan`/`--crawl`, which
  need a fresh `whatweb`) or the ports don't match, it reruns those phases
  anyway — it's a shortcut, never at the cost of showing stale data.
- `searchsploit` is an **offline** query against a local exploit-db copy: it
  never downloads or runs anything. Version-based matching gives false
  positives — **verify every EDB-ID by hand** (`searchsploit -x EDB-ID` to
  read it, `-m EDB-ID` to copy it).
- If run with `sudo`, ownership of `~/htb/<ip>/` gets handed back to the
  real user (`SUDO_UID`): the **folders** right as they're created (so you
  can delete/read their contents even if you Ctrl-C), and the **files**
  (nmap, logs, reports) once it's done — so you can edit reports without
  `sudo`.
- **Correct `Host:` header behind a WAF/CDN with SNI** (Cloudflare,
  Cloudfront...): the whole web pipeline (`whatweb`, `wafw00f`, the
  `.git`/`.env`/etc. checks, nikto, wpscan, joomscan, katana, ffuf and the
  `http-*` NSE scripts) uses the target's **real hostname**, not the bare
  IP — hitting the IP without the right Host gives a generic 403/block for
  EVERYTHING and the recon comes back "clean" by mistake. If the target was
  given as a bare IP (no known hostname), it still uses the IP like before.
- If you suspect vhost fuzzing is hiding a hit (a known `-ac` bug in ffuf,
  issue #387), rerun by hand with `-fs <default response size>`.
- No recursion in ffuf by default (there's an `-ac`+`-recursion`+JSON bug
  that empties results). If you want it: `-recursion -recursion-depth 1` by
  hand.

## Safe for exam use

By default `palantir` is pure enumeration — nmap/ffuf/footprinting/default
credentials — **nothing is auto-exploited**, so it doesn't conflict with
exam policies that ban automated exploitation (the kind that rules out
Nessus/OpenVAS/Metasploit `autopwn`/sqlmap, none of which this tool uses or
wraps). The one flag worth double-checking before an exam is **`--nuclei`**
(opt-in, off by default): some community templates don't just detect, they
run a full PoC — review which templates would run before using it in an
exam, or skip it altogether.

The automatic SAM/LSA dump after a confirmed `(Pwn3d!)` (phase 5d) isn't
"automated exploitation" either: it doesn't exploit any vulnerability, it
just uses an admin credential **you already provided** to read secrets that
same account can already see — the same technique as running
`secretsdump.py`/crackmapexec by hand, standard lateral-movement material.
**`certipy find`** (phase 5d, AD CS) is just as passive: it only enumerates
over LDAP with an already-validated credential, writes nothing. **noPac**
(phase 5d, SMB) doesn't exploit anything either: it only compares the size
of two TGTs to CONFIRM whether the DC is vulnerable (CVE-2021-42278/42287),
without ever impersonating anyone — actually exploiting it (`noPac.py
--impersonate`) stays a manual suggestion. **DCSync-rights**
(`secretsdump.py -just-dc-user krbtgt`, phase 5d) is a deliberate edge case:
unlike `certipy find`/noPac, it DOES extract a real secret (the krbtgt
hash) — but only THAT one, never a full NTDS dump, which is exactly the
line palantir already draws elsewhere (the SAM/LSA dump after a Pwn3d!,
LAPS): using a credential **you already provided** to read ONE secret that
same account can already see, not to empty the whole domain. What IS an
active escalation — requesting (`certipy req`) or forging (`certipy
shadow`) a certificate after finding an ESC1-8 template, actually
impersonating with `noPac.py`, or a full NTDS dump
(`secretsdump.py -just-dc`) after a confirmed DCSync — palantir **never**
runs on its own: it's always left as a manual suggestion with the ready
command, so you decide when to take that step (same criterion as the NTDS
dump, see [CHANGELOG.md](CHANGELOG.md)). The **💡 tips** in the Quick Wins
box (what approach to follow for a finding category — AXFR, Zerologon,
writable shares...) are just as passive as everything above: plain text
explaining the reasoning, never a new command or a suggestion palantir
wasn't already making manually — designed specifically so palantir stays
usable in the OSCP exam without anything crossing into "automated
exploitation".

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the code layout and how to add a
new protocol. [CHANGELOG.md](CHANGELOG.md) has the project history.

## License

[MIT](LICENSE).

**Use only against targets you're explicitly authorized to test** (HTB/CPTS
labs, engagements with written permission).
