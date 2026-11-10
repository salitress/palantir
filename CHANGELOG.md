# Changelog

High-level history of `palantir.py`. This is a summary, not a line-by-line
commit log — see `git log` for that.

## Active Directory / Kerberos

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

## Scanning engine

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

## Web

- Extension-aware directory fuzzing (IIS/PHP/Tomcat/Apache), parallel
  fuzzing across multiple web ports, vhost fuzzing with automatic catch-all
  detection and a `crt.sh`/passive-DNS-seeded wordlist pass before the full
  dictionary.
- Passive checks for common sensitive paths/files, missing security headers,
  and WAF detection (`wafw00f`) before any fuzzing starts.
- Opt-in deeper scanners (`--nikto`, `--cms-scan`, `--crawl`, `--nuclei`) kept
  off by default — all of them are slower and noisier than the default
  recon pass.

## Known exploits & default credentials

- Offline `searchsploit` lookups per detected product/version, with a
  heuristic severity estimate (always verify the EDB-ID by hand).
- A curated, per-service list of default/installation credentials, each
  confirmed with a real read operation (not just "it connected") to avoid
  false positives — explicitly **not** brute force.

## Reporting

- Self-contained `report.html` (no CDNs), `report.md`, and `findings.json`,
  grouped by protocol, with a Quick Wins section (most actionable findings
  first, with the exact command and a short tip), a jump-to-section index,
  and copy buttons on every command.
- A preliminary report is written as soon as scanning/footprinting/default
  creds finish (before the slower fuzzing phases), auto-refreshing until the
  final report replaces it — so a run that's interrupted never leaves you
  without a report.

## Tooling / installation

- Pre-flight check for required/optional tools, with `--install-missing`
  installing what it can (`apt` where available, `pip`/`pipx` or a
  precompiled GitHub release binary otherwise — `jsmith.txt`, `kerbrute`,
  `certipy`, `adidnsdump`, `crt.sh`), always naming the exact source before
  asking.
- `--check-tools` to only report what's missing and how to install it,
  without touching the network.
