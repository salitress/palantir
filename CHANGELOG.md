# Changelog

High-level history of `palantir.py`. This is a summary, not a line-by-line
commit log — see `git log` for that.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- ADWS (9389/tcp, `mc-nmf`) now gets its own footprint: it's treated as an
  additional strong Domain Controller signal (alongside Kerberos), and flags
  the port with a note that the PowerShell `ActiveDirectory` module talks
  over this same channel instead of LDAP. Modern ADWS-based BloodHound
  collectors (SOAPHound, SOAPy and forks) exist but were deliberately left
  out as a concrete next-step: several active forks with differing syntax,
  none verified against their own source — consistent with this project's
  rule of never writing an unverified command into a public suggestion.
- New manual next-step suggestions in the LDAP credential-enum path, all
  suggestion-only (never executed): `addcomputer.py` + `rbcd.py` when
  MachineAccountQuota > 0, `raiseChild.py` when a parent-child forest trust
  is found, `ticketer.py` (Golden Ticket) when DCSync recovers the krbtgt
  hash, and `dacledit.py -action read` against a handful of high-value
  objects (Domain Admins, domain root, krbtgt, AdminSDHolder) whenever the
  domain is known. Every command's exact flags were verified against
  Impacket's own source before being added (several prior suggestions in
  this project had invented flags that didn't match any real tool).

### Changed

- PetitPotam/PrinterBug/PrintNightmare next-step suggestions in the MSRPC
  footprint now use the current, correct CLI syntax (`coercer coerce` /
  `petitpotam.py`, each with their real flags instead of an invented hybrid)
  and add two suggestions that were missing entirely: the ESC8 relay target
  (`ntlmrelayx.py --adcs` / `certipy relay`) and a dedicated PrintNightmare
  (CVE-2021-34527) RCE suggestion — noting it needs cube0x0's impacket fork
  and is largely mitigated by default on patched builds. Still manual,
  suggestion-only steps, never executed by palantir itself.

## [1.0.0] - 2026-11-10

Initial public release.

### Active Directory / Kerberos

- SMB/LDAP anonymous-session enumeration: RID cycling, group membership for
  high-value groups (Domain/Enterprise Admins, custom RID≥1000 groups),
  password policy via `rpcclient`/`nxc`, domain/forest trusts via
  `ldapsearch`, MachineAccountQuota.
- Zerologon (CVE-2020-1472) detection, SMB-signing-not-required detection,
  and automatic escalation to a reflective-relay finding when both appear on
  the same host (coercion via PrinterBug/PetitPotam + unsigned SMB).
- noPac (CVE-2021-42278/42287) check with an authenticated domain account.
- GPP cpassword / autologon recovery from SYSVOL (MS14-025).
- LAPS readability check, AD CS (`certipy find -vulnerable`, ESC1-8),
  DCSync-rights confirmation (krbtgt hash only, never a full NTDS dump).
- Kerberos user enumeration via `kerbrute userenum` (pre-auth, no lockout
  risk), with automatic `jsmith.txt`/seclists wordlist selection; optional
  automatic password spraying against discovered accounts (`--spray`).
- AS-REP roasting and Kerberoasting via `impacket-GetNPUsers`/`GetUserSPNs`
  once a domain credential is validated — queries the DC directly for every
  roastable account instead of depending on a guessed username list.
- Credential reuse across all detected services (phase 5d): a valid
  credential from one protocol is retried against the rest; a confirmed SMB
  admin session automatically triggers a SAM/LSA dump with that same
  credential (never a fresh exploitation attempt — just reading what that
  admin access already allows).
- Bulk credential spraying (`-U`/`-P`) via `hydra` for SSH/FTP/SMB (faster
  and more reliable than looping one `nxc` process per pair), falling back to
  `nxc` for the rest and for pass-the-hash.

### Scanning engine

- Four-phase nmap pipeline: ping-sweep (CIDR/range pruning), full TCP port
  discovery, `-sV` + curated NSE scripts, optional UDP sweep of the ports
  that matter (SNMP/TFTP/NTP/IPMI/DNS).
- `--stealth` (slower, less noisy timing) and `--tunnel`/`--pivoting` (connect
  scan, retry-tuned for a pivot/SOCKS relay that would otherwise drop open
  ports) modes, each tuned against real pivoting setups (ligolo-ng, chisel,
  sshuttle, proxychains).
- `--resume`: reuses existing nmap XML and, when ports/services are
  unchanged, the previous footprint/searchsploit/default-credentials results
  too — only fuzzing, reports, and newly provided credentials rerun.
- Multi-target support (CIDR, range, list, file) with optional parallel
  scanning (`--jobs N`) and an aggregate `index.html` across targets.

### Web

- Extension-aware directory fuzzing (IIS/PHP/Tomcat/Apache), parallel
  fuzzing across multiple web ports, vhost fuzzing with automatic catch-all
  detection and a `crt.sh`/passive-DNS-seeded wordlist pass before the full
  dictionary.
- Passive checks for common sensitive paths/files, missing security headers,
  and WAF detection (`wafw00f`) before any fuzzing starts.
- Opt-in deeper scanners (`--nikto`, `--cms-scan`, `--crawl`, `--nuclei`) kept
  off by default — all of them are slower and noisier than the default
  recon pass.

### Known exploits & default credentials

- Offline `searchsploit` lookups per detected product/version, with a
  heuristic severity estimate (always verify the EDB-ID by hand).
- A curated, per-service list of default/installation credentials, each
  confirmed with a real read operation (not just "it connected") to avoid
  false positives — explicitly **not** brute force.

### Reporting

- Self-contained `report.html` (no CDNs), `report.md`, and `findings.json`,
  grouped by protocol, with a Quick Wins section (most actionable findings
  first, with the exact command and a short tip), a jump-to-section index,
  and copy buttons on every command.
- A preliminary report is written as soon as scanning/footprinting/default
  creds finish (before the slower fuzzing phases), auto-refreshing until the
  final report replaces it — so a run that's interrupted never leaves you
  without a report.

### Tooling / installation

- Pre-flight check for required/optional tools, with `--install-missing`
  installing what it can (`apt` where available, `pip`/`pipx` or a
  precompiled GitHub release binary otherwise — `jsmith.txt`, `kerbrute`,
  `certipy`, `adidnsdump`, `crt.sh`), always naming the exact source before
  asking.
- `--check-tools` to only report what's missing and how to install it,
  without touching the network.
