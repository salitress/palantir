# Changelog

High-level history of `palantir.py`. This is a summary, not a line-by-line
commit log — see `git log` for that.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- LDAP signing / LDAPS channel binding: read from the banner nxc already prints on every
  `nxc ldap` connection (no extra module — the old dedicated `-M ldap-checker` module is
  retired upstream, confirmed reading nxc's own source). Not enforced → "media" finding
  (NTLM relay surface toward LDAP/LDAPS, e.g. AD CS ESC8).
- Pre-created ("pre2k", NT4-compatible) computer accounts: detected read-only over LDAP
  (same authenticated bind already used for domain-trust lookups). These accounts get a
  predictable default password (lowercase computer name, 14 chars) — palantir only reports
  that they exist; next-step suggests nxc's `-M pre2k` (which does try that password, one
  guess per account) to actually get a TGT.
- ESC1 + MachineAccountQuota>0 cross-reference: when both are confirmed on the same
  credential, a next-step explains the TEMPLATE_DENIED path (template enrollment likely
  restricted to Domain Computers) — create a own computer account, request the ESC1
  certificate as that account with `-upn administrator@domain -sid DOMAIN_SID-500`, then
  `certipy auth`. All manual, never chained automatically.
- Two new manual next-step suggestions, neither executed automatically: `-M timeroast`
  (MS-SNTP roasting of computer/trust account hashes, with a bounded RID range instead of
  the module's 1-2^31 default) in the Kerberos footprint, and `-M badsuccessor` (dMSA
  privilege-escalation check, only applicable with a Windows Server 2025 DC) alongside the
  existing `dacledit.py` ACL-review suggestion.
- When `--user-list`/`--pass-list` crosses into real password-spraying territory (same
  threshold as the existing lockout warning), points to brutespray's lockout-aware `-spray`
  mode as a better-paced alternative, reading the `.gnmap`/`.xml` nmap already saved for
  that target instead of re-scanning. Suggestion only, same as the rest of this list.
- New cross-protocol summary (`_suggest_brutespray`, run once per target alongside the
  existing SMB+MSRPC relay combiner): when 2+ dictionary-crackable services are found on
  the same host, suggests one brutespray pass against the `.gnmap` nmap already saved
  instead of running hydra once per protocol — each protocol's own hydra suggestion stays,
  this is additive. Suggestion only.
- Phase 5d (provided credentials) now actually runs brutespray against telnet/pop3/imap/
  redis/snmp/smtp — the only protocols that had no automated credential-testing path at all
  (no nxc module, not mysql/postgres either), so `--user/--pass/--creds-file` and
  `--user-list/--pass-list` used to silently skip them. New, separate function
  (`brutespray_extra_creds_check`/`_brutespray_bulk`) — doesn't touch the existing,
  already-tested `provided_creds_check` hydra/nxc path for the protocols that already had
  one. Verified against a real, locally-run brutespray build (not just documentation):
  tested against an actual HTTP Basic Auth server and a real SSH server, both confirming the
  same `brutespray-summary.json` schema and that the found credential is parsed correctly in
  both exact-pairs (`-C`) and crossed user×password (`-u`/`-p`) mode. User/password always
  via 0600 temp files, never in argv, same convention as the existing hydra path. That same
  real run caught brutespray writing `brutespray-checkpoint.json`/`.jsonl` into whatever
  directory it's invoked from by default (not into `-o`) — palantir now always passes
  `-checkpoint` pointing inside its own temp dir, so a brutespray run never leaves stray
  files in the directory palantir itself was launched from.

### Fixed

- The shared `index.html` (`<outdir>/index.html`, listing every target scanned into that
  output directory) could end up permanently un-writable after mixing a `sudo` run with a
  later non-`sudo` run — found live: `no pude escribir el índice: [Errno 13] Permission
  denied`. `chown_dirs`/`chown_results` hand the real user ownership of the per-target
  *folders* under `sudo`, but never of this one file, since it lives in the parent output
  directory rather than inside any single target's folder — so a first `sudo` run leaves it
  root-owned, and a later non-`sudo` run can't overwrite it even though the directory holding
  it was already fixed. `write_index` now chowns the file itself right after writing it, and
  a `PermissionError` specifically (as opposed to any other `OSError`) now prints the exact
  `sudo chown` command to unstick an index left over from before this fix.
- A comma-separated target list like `172.16.6.3,50` silently scanned a bogus second target
  instead of failing clearly — found live, mid-run, against a real target. `172.16.6.3,50`
  splits into two specs (`172.16.6.3` and `50`); the bare `50` isn't a valid IP/CIDR/range, so
  it fell through to the hostname-resolution fallback, and `socket.gethostbyname()` inherits
  the old BSD `inet_aton()` shorthand that treats a purely numeric token as a packed 32-bit
  integer — `50` resolved straight to `0.0.0.50` (same for `172.50` -> `172.0.0.50`, or a
  `0x`/octal-looking token) instead of failing to resolve. The result: a second, nonsense
  target scanned for the full run time, with its own junk output folder, and no indication of
  what went wrong beyond a "2 objetivos" count that didn't match what was actually typed.
  `expand_targets` now rejects anything shaped like this numeric-shorthand notation before
  trying to resolve it, with a clear warning instead of silently fabricating a target.
- A finding/next-step line containing a real embedded newline (or tab/carriage return) broke
  the terminal "Quick wins" box border — found from the same real target as the two
  redundant-suggestion bugs above: a katana-discovered HTML comment was multi-line in the raw
  markup (`Disable file uploads untill maintenance\n         <button ...>`), and that raw
  `\n` + indentation ended up inside the finding text itself. `box()`'s width math
  (`_vis_len`/`_vis_wrap`) counted the embedded `\n` as a normal, width-1 character, but the
  terminal actually breaks the line there when printing — so the rest of that row (padding +
  closing border) landed on an orphan line with no border of its own, exactly like the real
  screenshot. `box()` now neutralizes `\r`/`\n`/`\t` in every line before measuring or
  wrapping it, so this can't happen regardless of which finding/next-step text it came from.
- Two "quick win" next-steps could ask to manually redo, by hand, a check palantir had
  already run and already confirmed negative — found going command-by-command through a
  real "Quick wins" card against a live target: `impacket-rpcdump ip | grep -iE
  'MS-RPRN|MS-PAR|MS-EFSR|spool'` showed up in the MSRPC footprint's next-steps even when
  `rpcdump` had already run successfully and found neither (the suggestion was only meant
  for when the tool is missing or the run failed, not when it ran fine and the answer was
  just "no"); and the IIS footprint suggested `curl -s url/web.config ; curl -s
  url/trace.axd ; curl -s url/elmah.axd` unconditionally whenever a host was IIS, which is
  the exact same three files, behind the exact same `if _is_iis(...)` condition, that the
  content-verified `WEB_SENSITIVE["aspnet"]` check a few lines above already GETs and
  confirms (with actual body-content verification, unlike a bare `curl`). The second one is
  just removed — there's no scenario where that condition is true and the automatic check
  didn't already run. `davtest` stays as a manual-only suggestion in both cases it was
  already in (it's a write to the target, never auto-run, by design).
- A provided credential (`--user`/`--pass`/`--creds-file`) could get silently treated as
  invalid for SMB/LDAP if the one-shot confirmation check (`nxc <proto> ip -u user -p pass`,
  40s timeout) got cut off by a slow/loaded real target before `nxc` printed its `[+]` —
  found against a real, genuinely slow shared HTB lab target where the exact same command
  went from hanging to responding in 3s minutes apart. Partial output from a timed-out run
  almost never contains `[+]`, so the credential looked like it failed and the entire
  downstream enumeration with it (`--users`/`--groups`/MAQ/trusts/DCSync-rights/AS-REP/
  Kerberoast for LDAP, `--shares`/SAM-LSA for SMB) was skipped — with nothing beyond the
  generic timeout warning to say why nothing else showed up. Now retries once with 120s
  before giving up on the credential.
- Finding text with a long unbroken string (an NTLM/plaintext secret from an LSA dump, for
  example) could overflow past the edge of its card in the HTML report instead of wrapping —
  a classic flexbox gap: the text `<span>` had neither `min-width:0` nor `overflow-wrap`, so
  it refused to shrink below its unwrapped width. Confirmed with a real report where a
  credential line overflowed exactly like that; fixed with both properties on the finding
  text element.
- The target index (`index.html`) could list the same target multiple times with identical
  ports/findings/timestamp — found against a real scan with 2 discovered hostnames, which
  showed up as 3 rows. `_scan_outdir_targets` used `Path.is_dir()`, which follows symlinks,
  so each per-hostname convenience symlink `_make_hostname_symlinks` creates (so you can
  `cd dc01.corp.local` instead of the bare IP) was counted as a separate scanned target
  pointing at the same `findings.json`, instead of being recognized as an alias for the one
  real target folder. Symlinks are now skipped explicitly.
- brutespray credential testing for SNMP and Redis was silently broken for the most common
  case (`--user`/`--pass`/`--creds-file`, or a `--user-list`/`--pass-list` combo small enough
  to go through as explicit pairs) — found by actually running a real end-to-end CLI scan
  against a real redis-server and a real snmpd, not just unit-level calls:
  - **SNMP**: in brutespray's legacy community-string mode, only the `user` field of a pair
    is tried as-is — the `password` field gets MD5-hashed before being tried
    (`brute/snmp.go`), so a correct community string passed the normal way (as a password
    candidate) never matched. Every candidate palantir receives (from either `--user`/
    `--user-list` or `--pass`/`--pass-list`) is now tried in the `user` position instead.
  - **Redis**: passing any non-empty username in `-C user:pass` pairs mode makes brutespray's
    go-redis client attempt a Redis 6+ ACL-style 2-argument `AUTH user pass`, which fails
    against a plain `requirepass` server even with the correct password; brutespray's own
    `-u`/`-p` crossed mode silently drops the username for this service and succeeds.
    palantir now always uses crossed mode for Redis and never pairs mode, regardless of
    whether the credentials came in as explicit pairs or a list.
  Also: the Redis finding text used to hide the found password behind "usuario sin
  identificar" whenever there was no username (which, per the above, is always the case for
  Redis) — it was written to only show a credential when *both* a user and a password were
  present.
- `brutespray` was entirely missing from the central tool registry (`TOOL_PKGS`,
  `_FETCHABLE_RESOURCES`): `--check-tools`/`--install-missing` didn't know about it, and with
  credentials to test but the binary not installed, `brutespray_extra_creds_check` just
  returned `[]` — no indication in the report that telnet/pop3/imap/redis/snmp/smtp went
  untested for lack of a tool. Registered like `crt.sh`/`kerbrute` (precompiled release
  binary, no apt package, installable without Go via `--install-missing`), and the
  not-installed case now leaves one footprint with `missing: ["brutespray"]` instead of
  vanishing silently.
- Terminal banner (orbe + wordmark): the orb's equator row had an
  inconsistent shading ramp (a dip plus a skipped level) that its
  neighboring rows didn't have — now a smooth, still-symmetric gradient.
  The wordmark's vertical gradient (`_wm_color`) never actually reached its
  darkest color on any real face character, because the division included
  the wordmark's last row, which has no face glyphs at all (only the
  extruded-shadow edges) — fixed so the gradient reaches full color on the
  actual last face row. The wordmark's vertical centering against the orb
  was off by one row (it centered the whole 6-row block including that
  same no-face shadow row, instead of the 5 rows that actually have
  letters) — now the wordmark's letter body is centered on the orb's
  equator.

### Added

- With truecolor, the orb's shading scale now gets a 7-tone gradient
  (ember → red → orange → amber) instead of 3 flat colors — same approach
  the wordmark already used. No change without truecolor (flat colors as
  before).
- ADWS (9389/tcp, `mc-nmf`) now gets its own footprint: it's treated as an
  additional strong Domain Controller signal (alongside Kerberos), and
  suggests two alternatives to LDAP that talk over this same channel: the
  PowerShell `ActiveDirectory` module (needs RSAT + a shell on a domain
  host) and SoaPy (`logangoins/SOAPy` — the maintained upstream, verified
  against its own README; `xforcered/SoaPy` is just a 1-commit fork of it),
  a Linux tool that needs neither. SoaPy's own output still needs bofhound
  to become BloodHound-compatible JSON — that conversion step isn't
  automated here, just suggested.
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

- Terminal banner orb: redrawn as a dark crystal sphere with the Eye inside
  (zone-masked art — `_ORBE_ZONE` pairs 1:1 with `_ORBE_ART` so the same
  character can take a different color depending on which zone it's in:
  eye fire, glass near the rim, deeper/darker glass, the sphere's border),
  sitting on a black-iron pedestal whose claws climb the sides and merge
  into the glass. The eye keeps the same 7-tone fire gradient as before,
  plus a new near-white highlight (`@`) right at the pupil's edge. Verified
  before merging: every row of the art and the zone mask match exactly in
  count and length, every (zone, character) pair actually used in the art
  has a defined color in both the truecolor and plain-ANSI branches, and
  the sphere itself is vertically and horizontally symmetric.
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
