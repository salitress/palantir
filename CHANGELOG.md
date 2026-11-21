# Changelog

High-level history of `palantir.py`. This is a summary, not a line-by-line
commit log — see `git log` for that.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `_dump_sam_lsa` now chains a third step after `--sam`/`--lsa` on every confirmed SMB
  `(Pwn3d!)`: `nxc smb ... -M lsassy`, a remote memory dump of `lsass.exe` (comsvcs.dll
  MiniDump, module source confirmed against nxc's own `nxc/modules/lsassy.py`). Unlike
  `--sam` (local accounts only) and `--lsa` (secrets at rest: DPAPI/NL$KM/service creds),
  lsassy surfaces the credential (plaintext or NTLM hash) of **any account with a live logon
  session on the box right now** — local or domain — which is how a stray Domain Admin RDP
  session on a compromised host turns into a direct DA hash. Findings are explicit that this
  is noisier than `--sam`/`--lsa` (one of the most heavily monitored EDR/Defender IOCs) and
  that it can fail cleanly against Credential Guard or LSA running as a Protected Process
  (RunAsPPL) even with real admin. Found credentials feed the cross-protocol reuse pool like
  SAM/LSA already did; a failed on-target cleanup (`[OPSEC] Failed to delete...`) is promoted
  to its own finding (an artifact left on disk); any Kerberos tickets lsassy saved locally are
  pointed to in a next-step. No new dependency: `lsassy` is a hard pip dependency of nxc itself.
- The abusable-ACL audit (added in 1.2.0) now also checks individual high-value **accounts**,
  not just groups: control over the built-in `Administrator` account (`nxc -M daclread -o
  TARGET=Administrator` — `TARGET` resolves by `sAMAccountName`, confirmed generic for users
  too against nxc's own help text/source) means you can reset its password directly and log
  in as it, without ever joining a group. Real gap found live: the audit already flagged
  `FullControl`/`WriteDACL`/.../`Self` over `Enterprise Admins`/`Administrators`, but the
  actual path the operator took was resetting `Administrator`'s password, which the
  group-only check never saw. `_acl_abuse_cmds` gained a `kind` parameter (`"group"`,
  unchanged default, vs `"account"`) so the same right→command-chain logic now ends in
  `bloodyAD ... set password` instead of `add groupMember` when the target is an account.
  MVP: only the well-known `Administrator` account, not a dynamic sweep of every current
  member of Domain Admins/Enterprise Admins/Administrators (documented as a follow-up).

### Changed

- `kerbrute userenum` is now always the **last resort** for AD user enumeration, never the
  first thing tried. It's a wordlist guess against Kerberos pre-auth (minutes, depends on
  the list), while two faster/more authoritative paths can already give the full user list in
  the same run:
  - **Anonymous SMB/LDAP enum (same Fase 5)**: `footprint_services` now processes `smb`/`ldap`
    buckets *before* `kerberos` (previously it followed port number, so 88/tcp always went
    first even though 139/389/445 usually follow right after). `_smb_ad_enum`'s RID cycling and
    `fp_ldap`'s anonymous `--users` now also write any users they find to `ad_users.txt` (same
    merge-not-overwrite helper kerbrute already used). If that anonymous session already found
    users, `fp_kerberos` skips kerbrute entirely.
  - **Credentials provided on the CLI** (`-u`/`-p`/`-H`/`--creds-file`/`-U`/`-P`): `fp_kerberos`
    now receives `has_creds` and, when set, does *not* run kerbrute in Fase 5 — it leaves a
    `_pending_kerbrute` marker instead. Fase 5d (right after, in the same run) tries that
    credential against SMB `--rid-brute` / LDAP `--users`, which is authoritative (the real
    domain list), not a guess. A new `_run_deferred_kerbrute_fallback`, called once Fase 5d
    finishes, checks `ad_users.txt`: if the credential actually found users, kerbrute never
    runs; if it didn't (bad credential, restrictive ACL…), kerbrute runs then as the fallback it
    always was before credentials were in the picture — same de-dup as before for the AS-REP
    roast next-step so it doesn't show up twice.
  - Real-world case that prompted this: `-u CT059 -p charlie1` against a DC still ran the full
    `kerbrute userenum` wordlist (jsmith.txt) in Fase 5, even though Fase 5d, seconds later,
    was going to enumerate the complete domain user list with that exact credential anyway.

### Fixed

Comprehensive audit of `palantir.py` (external-tool output formats verified against upstream
source: NetExec, ropnop/kerbrute, logangoins/SOAPy, brutespray). Each fix has a `--selftest`
test that fails without it. Highlights, by class:

- **Finding→command association in Quick Wins** (operator-reported): a critical ACL finding
  (`FullControl/WriteDACL` over `Domain Admins`) showed unrelated AS-REP/Kerberoast commands
  instead of the correct `bloodyAD add groupMember`; same class on SMB relay, SMTP open-relay,
  FTP bounce and exposed `.git`/`.env`/WebDAV. Findings now carry their exploit command from the
  point they're raised (`_attach_cmd`), `_STRONG_KW_RE` gained ACL/relay tokens, and the Quick
  Wins command de-dup compares the command without its inline comment (no more duplicates).
- **Partial results presented as complete** (operator-reported, over the tunnel): DB enum,
  `kerbrute userenum`, bulk spray, `fp_smb` Zerologon/MS17-010, and credentialed Kerberoast/AS-REP
  now check `rc`/retry on empty and mark results `(PARCIAL/POSIBLEMENTE INCOMPLETO)` instead of
  reporting a truncated result as final; `ffuf` throttles under `--tunnel`.
- **Crashes that aborted the whole target** (no report at all): synthetic MSSQL port from the SQL
  Browser lacked `state`/`tunnel` (KeyError); credential-feedback KeyError on MySQL/PostgreSQL;
  unguarded deferred-kerbrute call; per-target `-sT` fallback latching under `--jobs`.
- **Guest-mapping as a false valid login**: `(Guest)` is no longer counted as a real login for a
  provided/default credential (SMB `map to guest = Bad User`).
- **Wrong port / missing `--port`**: SMB/LDAP spray-confirm now emit `--port` for non-default
  ports; `fp_vnc`/`fp_redis` loop per port; VNC uses the real `No Auth:True` banner token.
- **Kerberos/NXC/brutespray parsers**: kerbrute no-preauth (separate line), `VALID LOGIN WITH
  ERROR`, lockout vs network abort, `-M timeroast` option that crashed the module, `SOAPy` binary
  case; brutespray scheme by service, `-r` default, no retry-wrapper on an active brute.
- **Severity / correctness**: `_exploit_severity` matches short acronyms (rce/sqli/…) by whole
  word (no more `source`→CRITICA); modern-OS exploit downgrade reads `smb-os-discovery` from the
  host-script where it actually lives; exploit summary sorts before listing sample EDB-IDs.
- **Privacy**: the 1-by-1 provided-credential path no longer leaks the plaintext password into the
  stored step command/output/note (it did, even for failed attempts) — only the finding shows it.
- **Report leakage**: internal `_`-prefixed footprint keys (e.g. `_ldap_signing_disabled`) are no
  longer serialized into `findings.json`.
- **HTML report**: per-target port table gains a **state** column (UDP `open|filtered` vs confirmed
  `open`); vhosts of the same domain are merged into one table; `--vhost-names` size shows `n/d`
  instead of `- b`; the exploits pill/TOC count distinct EDB-IDs.

See `MEJORAS.md` for the read-only/detection-only feature ideas from the same audit (proposals, not
implemented) and the design decisions on what palantir deliberately does **not** do.

## [1.2.0] - 2026-11-21

### Added

- `bloodyAD` is now a known tool: it shows up in `--check-tools` and `--install-missing` installs
  it (`pipx install bloodyAD`), like certipy/adidnsdump. palantir never runs it — it's only
  suggested by the ACL audit's abuse next-steps — but now the operator can have it ready in one
  step instead of hitting a "command not found" when they go to use the suggestion.
- **Abusable-ACL audit with a provided credential — a "one-question BloodHound"** for the single
  highest-value question: does *this* credential already have a direct path to Domain Admin
  through a misconfigured ACL, without standing up BloodHound/Neo4j? Using `nxc -M daclread`
  (filtered to the credential as the trustee, format confirmed against nxc's own source), on a DC
  it now checks:
  - **DCSync viability** — `DS-Replication-Get-Changes[-All]` over the domain head (`RIGHTS=DCSync`)
    → critical: dump every hash (krbtgt included) without being an admin, with the exact
    `impacket-secretsdump -just-dc` command.
  - **Control over high-value groups** — `GenericAll` / `WriteDACL` / `WriteOwner` / `GenericWrite`
    / `WriteProperties` / `Self` over Domain Admins, Enterprise Admins or Administrators → critical,
    with the concrete abuse chain. The abuse commands use **bloodyAD** (`add groupMember`, and for
    `WriteDACL`/`WriteOwner` the `add genericAll` / `set owner` chain), not `net rpc group addmem`:
    bloodyAD goes over LDAP/NTLM and works against an IP, whereas `net rpc` tries Kerberos first and
    fails with `Failed to connect to IPC$` against an IP target with no FQDN (confirmed live).
    Pass-the-hash uses bloodyAD's `-p :<hash>`.

  This is the gap a real assessment hit: `CT059` had `GenericAll` over Domain Admins and that was
  the actual path to DA, but palantir had no way to see it on its own — it had to be found by hand
  with BloodHound. Detection is read-only (daclread only *reads* the DACL); the abuse stays a
  manual next-step, exactly like the Zerologon/noPac exploit suggestions.

### Changed

- The WMI/SMB **RCE next-steps** (`impacket-wmiexec`, `nxc … -x`) now spell out that they need
  **local admin** on the target, not just valid domain credentials — a standard domain account
  gets `rpc_s_access_denied` / `STATUS_ACCESS_DENIED` (confirmed live: `CT059` authenticated fine
  but `impacket-wmiexec` came back `rpc_s_access_denied` because it isn't admin on the DC). The
  comment said "con credenciales válidas", which over-promised RCE.
- A valid **anonymous (null/guest) session over WMI or LDAP** is now reported as `media`, not
  `alta`. On those two protocols an anonymous bind is common and low-value by itself (WMI can't
  query anything without privileges; an anonymous LDAP bind that can't read is already reported
  separately), so flagging it `alta` overstated it (flagged live). SMB/WinRM/RDP/MSSQL null
  sessions stay `alta` (shares/shell/direct access), and `Administrator` with a blank password
  stays `alta` on every protocol — that's never low-value.

### Fixed

- Domain/DC-level findings no longer appear once **per credential**. noPac, "no account lockout",
  Domain/Enterprise Admins membership, MachineAccountQuota and the domain user count are
  properties of the domain, not of the credential that confirmed them — but with 2+ provided
  credentials (common after a `--resume` that adds a new one) they showed up two or three times,
  once tagged `(cred mssqlsvc)`, once `(cred BR086)`, etc. (flagged live, "error users ad"). noPac
  was the worst case: unlike the others it wasn't deduplicated at all within a single run; it now
  goes through the same `_add_once` marker. And the `--resume` accumulation merge
  (`_merge_creds_provided_footprint`) now dedups findings by a key that collapses `(cred <X>)` →
  `(cred)`, so the same domain-level finding from an older run and this one counts as one.
  Genuinely per-credential findings (`credencial válida — «user:secret»`, `Pwn3d!`) don't carry a
  `(cred X)` tag, so they're untouched and still listed per credential.
- A **provided hash** is now shown in its finding, like a provided password. `nxc … -H <hash>`
  produced `credencial aportada válida — «mssqlsvc:***»`, masking the operator's own input and
  making it impossible to tell which pass-the-hash credential worked (flagged live, "se esconde el
  hash"). The finding now shows the hash; the step's raw output still masks it for dump hygiene,
  and the displayed command still uses `-H '***'` to keep it out of `commands.log`.
- `maybe_add_hosts` (`/etc/hosts` prompt) now matches an existing entry by **exact hostname
  token**, case-insensitively, instead of a `\b`-bounded substring regex that treated
  `inlanefreight.local` as already present whenever `dc01.inlanefreight.local` was in the file
  (the `.` counts as a word boundary). It also says so — "(/etc/hosts) ya está: … — no hace falta
  añadir nada" — instead of silently skipping, and when only some names are missing it names which.

### Changed

- `--resume` is much quieter on screen when it reuses a previous run as-is. It no longer re-dumps
  the full port table (every NSE script included) nor the whole searchsploit exploit table — both
  are byte-for-byte repeats of the previous run and only added noise before getting to the actual
  new work (Fase 5d). Each is replaced by a one-line summary, with the full detail still in
  `report.html`. A fresh scan, or a resume where anything changed (different ports, a re-scan),
  still prints both in full as before.

### Added

- MSSQL is now footprinted and credential-tested even when the TCP port scan didn't see 1433
  open, as long as the **SQL Server Browser** (1434/udp) advertised the instance's TCP port
  (`… TCPPort: 1433`). Over a tunnel 1433 often comes back filtered in the `-sT` while the
  instance still accepts connections — seen live on SQL01 (172.16.7.60): `impacket-mssqlclient`
  logged in with the `netdb` credential recovered from a share's `web.config`, but palantir never
  tried MSSQL because 1433 wasn't in the scan. `_mssql_from_sql_browser` reads the Browser's
  advertised port (format confirmed against real nmap output) and adds a synthetic MSSQL service
  on it, so fp_mssql and the provided-credential check run against it. Needs the UDP scan (root)
  for the Browser to be seen; with no UDP there's no signal and nothing is assumed.

## [1.1.0] - 2026-11-20

### Added

- Host identity (NetBIOS name + AD domain) is now also recovered from the **nxc banner** saved in
  the footprint steps (`(name:HOST) (domain:DOM)`), not just from nmap NSE / DNS. Found live with
  SQL01 (172.16.7.60): a host with only 139 open (no 445/LDAP/DNS) had its name "SQL01" and domain
  "inlanefreight.local" highlighted all over the report, yet the target was labelled only by IP
  because nbstat/smb-os-discovery (need 445/3389) and `discover_domains` (nmap scripts/banners)
  never saw them — but every nxc line did. `_nxc_identity_from_footprints` extracts them (domain
  only when it's a real FQDN, so a workgroup's `(domain:HOSTNAME)` is ignored), and run_one folds
  the domain and the derived `host.domain` FQDN into the target's domain list, so the report shows
  the hostname like every other target and the `DOMINIO` placeholder fills itself.

- Live progress heartbeat for the **silent** credentialed-enumeration queries in Fase 5d.
  `_run_capture_progressive` already heartbeat the long `--users`/`--rid-brute` calls, but the
  dozen-plus `_run_capture_retry` queries that follow (`--groups "Domain Admins"`, `-M
  gpp_password`, `-M nopac`, `maq`, `--pso`, `-M obsolete`, Kerberoast/AS-REP via impacket…)
  ran completely mute — each opens its own connection and, over a tunnel, can sit silent for up
  to its 90s timeout, so the screen froze for minutes and looked hung. Diagnosed live by
  snapshotting the running nxc process twice seconds apart: it had advanced from `nxc ldap …
  --groups "Domain Admins"` to `nxc smb … -M gpp_password`, proving it was progressing, not
  stuck — just invisibly. `_run_capture_retry` now prints a `… <query> en curso (Ns por el
  túnel)…` line every 20s for any call that outlasts the interval (fast calls stay silent). The
  label comes from a new `_cmd_label`, which shows the binary + protocol + action flags
  (`--groups`, `-M <mod>`) but **never** positional args or auth values — so an
  `impacket-GetUserSPNs dominio/user:pass …` (password in the positional argv) can't leak into
  the progress line. Regression-tested for exactly that no-leak property.

- `--resume` now **accumulates** Fase 5d (provided-credentials) findings across runs instead
  of silently losing them. Found via a direct question before it ever caused real damage:
  running `--resume -u user1 -p pass1`, then later `--resume -u user2 -p pass2` (or even
  `--resume` with no credentials at all) made every finding user1's credential had confirmed
  for that protocol vanish — not overwritten in some visible way, just gone, because
  `_phase == "creds_provided"` footprints were never reloaded from the previous
  `findings.json` (only `"footprint"`/`"creds_default"` were), and `write_reports` rewrites
  the whole file from whatever is in memory for that run. `_merge_creds_provided_footprint`
  now combines the old and new footprint-dict for the same protocol (newest findings/steps/
  next-steps first, owner's untouched protocols from before kept as-is, exact duplicates not
  repeated) before saving — the full report keeps everything every credential ever confirmed
  for a target, not just the most recent one tried.
- Five more nxc checks, all auto-run, all solo-lectura (ninguno escribe/explota nada) and all
  verified against nxc's own real source on GitHub before writing a parser — not guessed, same
  standard as the rest of this list:
  - `ms17-010` (EternalBlue, CVE-2017-0143 y relacionadas) y `smbghost` (CVE-2020-0796): igual
    que Zerologon ya hacía, pero para CUALQUIER host SMB (no solo un DC) y sin credenciales —
    dos comprobaciones de un solo paquete crudo por socket, nxc no explota nada. EternalBlue
    además detecta si el host ya está infectado con DoublePulsar.
  - `webdav`: ¿está el servicio WebClient activo en el equipo? (pipe `DAV RPC Service` en
    IPC$). Si lo está, es una superficie de coacción NTLM alternativa al spooler/MS-EFSR — la
    víctima se puede forzar a autenticarse por HTTP en vez de SMB.
  - `--pso` (LDAP, con credenciales): políticas de contraseña granulares (Fine-Grained
    Password Policy) — pueden ser más laxas que la política del dominio para ciertos
    usuarios/grupos. Ya no es un módulo (`-M pso` está retirado upstream, "moved to the core
    option --pso" en su propio código fuente); se usa el flag nativo.
  - `-M obsolete` (LDAP, con credenciales): equipos del dominio con un SO Windows sin soporte
    (XP/Vista/7/8/Server 2003-2012) — candidatos directos a movimiento lateral si alguno sigue
    vivo en la red.
- `_run_capture_progressive` (el timeout adaptativo de arriba) ahora imprime un latido cada ~20s
  mientras espera ("… sigue esperando (N línea(s) de salida hasta ahora, Xs desde la última
  nueva)"), SIEMPRE, incluso cuando se llama con `quiet=True` — reportado en vivo: contra un AD
  con más de 2000 usuarios, el operador llevaba 15 minutos sin NINGUNA señal en pantalla durante
  `--users`/`--rid-brute` y no tenía forma de distinguir "sigue avanzando, tardará lo que tarde"
  de "se quedó colgado". `ad_users.txt` tampoco ayuda ahí: solo se escribe UNA VEZ, cuando el
  comando termina del todo, no según va encontrando usuarios.
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

- Adaptive, progress-aware timeout (`_run_capture_progressive`) for the nxc enumeration
  commands whose runtime scales with the size of the AD domain (`--users` by SMB and LDAP,
  `--rid-brute` anonymous and credentialed) — reported live: an operator suspected a user got
  missed because the enumeration looked like it had been cut off mid-run against a large
  domain. These used to run under a plain fixed timeout (e.g. 120s for LDAP `--users`), which
  on a domain with hundreds/thousands of accounts can legitimately still be mid-enumeration
  when it fires, silently truncating the result with no indication anything was cut short.
  Instead of a fixed deadline, the new wrapper runs the command via `Popen` (with
  `PYTHONUNBUFFERED=1`, since nxc is Python and block-buffers its stdout once it isn't a
  TTY — without this nothing would appear to "grow" until the process exits) and tracks
  whether new output keeps arriving: as long as it does, it keeps waiting; once output stalls
  for 5 minutes straight, it's cut there (most likely finished responding or hung); if the
  process exits on its own, it returns immediately without waiting out any timer. A generous
  absolute ceiling (30 min) still protects against a truly runaway process. Verified with real
  (non-mocked) subprocesses exercising growth-then-stall, early natural exit, and the safety
  ceiling under continuous growth.

### Changed

- Per-protocol findings are now grouped **general-first, then credential by credential** (each
  group in severity order) instead of pure severity order. With two provided credentials (e.g.
  BR086 and AB920) their findings used to interleave — you'd read one user's results, then the
  other's, then the first user's again further down. `_findings_grouped` keeps each credential's
  findings together; applied to the terminal, HTML and Markdown per-protocol blocks (Quick Wins
  and the global summary stay severity-only). Credential detection is tolerant: `«Department
  Shares»` without a `user:pass` colon is not mistaken for a credential.
- The content spider (`nxc --spider … --content`) now uses the progressive capture (adaptive,
  with heartbeat) instead of a fixed 180s timeout. Over a tunnel a deep share could take longer
  and was cut mid-traversal (seen live stuck at `[*] Spidering .`), missing loot in deep
  subdirectories; it now follows real progress and only stops after 5 min with no new output.
- Fase 4 (manual banner grabbing) no longer re-opens live sockets under `--resume`. It was the
  only phase still doing real network work on a resume — Fases 1-3 already reuse the cached nmap
  XML, but banner grabbing fired fresh socket connects to every port (4-parallel, 8s timeout
  each over a tunnel, some ports burning the full timeout) right before Fase 5d, just to
  re-learn banners already saved in the previous run's `findings.json`. When the ports/services
  match the previous run (same `_resume_reuse_ok` criterion as the rest of resume), it now
  reuses the stored `banner` field per `(port, proto)` and prints a `[--resume] reutilizo los
  banners…` line instead of re-probing. A port not present in the previous run keeps whatever it
  already had.
- Fase 5d's LDAP preview line now reads `AS-REP/Kerberoast (impacket GetNPUsers/GetUserSPNs)`
  instead of `--asreproast/--kerberoasting`. The actual execution already uses impacket (per the
  operator's explicit request), but the on-screen preview still named nxc's flags, which was
  misleading — it looked like palantir ran roasting through nxc when it doesn't.
- Fase 5d (provided credentials) now tries **LDAP before SMB** (`_CREDS_PROTO_PRIORITY`
  reordered). Prompted by a live comparison: `nxc ldap IP --users` against a DC with ~2900
  domain accounts finished in under 30s, while the equivalent `nxc smb IP --users`/
  `--rid-brute` (SAMR, RID-cycling over IPC$) was still running 15+ minutes later on the same
  domain. Both ultimately enumerate the same domain user list, so once LDAP has it (tracked via
  the existing `ad_seen`/`seen` marker `"usuarios del dominio"`, already shared between
  protocols to dedupe findings), `_creds_enum`'s SMB branch now skips its own `--users`/
  `--rid-brute` entirely and says so as an `info` finding — `--pass-pol` still runs (it's
  SMB-specific info LDAP doesn't have). If LDAP comes back with 0 users (e.g. LDAP access is
  restricted while SMB/SAMR isn't), SMB still runs its own enumeration as a fallback, same as
  before — the skip only fires when LDAP already produced a non-empty list.
- That same skip now also works **across `--resume` runs**, not just within one. Prompted by a
  direct question: if a previous run already got the complete domain user list with credential
  A, does testing a brand-new credential B later need to re-run `--users`/`--rid-brute` all over
  again? With AD's default ACLs, no — any authenticated domain bind sees the identical set of
  user objects (there's no per-querying-account "row-level" scoping unless the domain has
  non-standard deny ACEs or List Object Mode, which a normal lab doesn't), so re-enumerating for
  every new credential tested is wasted time, not new information. `provided_creds_check` takes
  a new `known_ad_users` flag that pre-seeds `ad_seen` with the `"usuarios del dominio"` marker;
  `run_one` sets it from `prev_creds_provided` (the --resume history already loaded for Fase 5d)
  whenever ANY earlier credential/run already produced that finding. Both skip messages (LDAP's
  own `--users`, SMB's `--users`/`--rid-brute`) now also spell out the assumption and give the
  manual command to force a recheck, in case a specific credential genuinely does see more.
- "No account lockout" (`AD: sin bloqueo de cuentas`, lockout None/0) is now an `alta`
  finding instead of `media`, so it surfaces in Quick Wins — flagged by the operator as more
  important than its old severity implied. On a DC, no lockout policy combined with the user
  list palantir has already enumerated is a direct, low-risk password-spraying path (spray one
  likely password across every account at once without locking anyone out), which is exactly
  the kind of "where do I start" entry Quick Wins exists for. A dedicated tip now explains the
  spray approach (and warns that "no lockout" still isn't "no logging" — each failure bumps
  `badPwdCount`). Bumped in all three places the finding is emitted (null-session SMB,
  null-session LDAP, and the credentialed `_surface_ad_enum` path).

### Fixed

- **SMB share names with spaces were truncated**, so the content spider targeted a share that
  doesn't exist and missed its loot. `_smb_readable_shares` split each `nxc --shares` line on
  whitespace and took the token before `READ`, so `Department Shares READ` became `Shares`. nxc's
  real format is `{name:<15} {perms:<22} {remark}` (confirmed in nxc/protocols/smb.py), i.e. the
  name can contain spaces and isn't truncated — so the parser now captures the whole name between
  the `SMB ip port host` prefix and the permissions column. Found live against INLANEFREIGHT: a
  `web.config` with a cleartext DB connection string lived in `Department Shares\IT\Private\…` and
  the spider never reached it because it was pointed at the non-existent `Shares`. The displayed
  spider command now also `shlex.quote`s the share name so a name with spaces is copy-pasteable.
- `--users`/`--rid-brute` results on a **member server (non-DC)** were mislabelled "N usuarios del
  dominio". On a non-DC those flags hit the local SAM and return LOCAL accounts (Administrator,
  Guest, DefaultAccount, WDAGUtilityAccount), not domain users — seen live on MS01/SQL01 as
  "4 usuarios del dominio" for what are 4 local accounts. `_surface_ad_enum` now takes `is_dc` and
  labels them "N cuentas locales (SAM)" with a `SAM` prefix on a non-DC (and the distinct marker
  keeps the DC-only SMB user-enum skip from firing on a local list). The DC path is unchanged.
- A finding's Quick Win padded its matched command with **unrelated** next-steps from the same
  footprint. `_cmds_for`, after matching a next-step by the finding's CVE/attack keyword, appended
  the rest of the protocol's next-steps up to n — so the Zerologon Quick Win showed its exploit
  and then, beneath it, an unrelated AS-REP roast command just because it sat in the same footprint
  (flagged live as confusing). It now returns only the keyword-matched commands; generic findings
  with no strong-keyword match still fall back to the first-N as before.
- The AS-REP/Kerberoast suggestions in the **anonymous** footprint next-steps still used nxc's
  `--asreproast`/`--kerberoasting` flags, while the authenticated path already uses impacket
  (`GetNPUsers`/`GetUserSPNs`) per the operator's explicit choice. Both anonymous sites now emit
  the impacket form with `DOMINIO/USER:PASS` placeholders (filled later once domain/credential are
  known), so roasting is consistently impacket everywhere, not nxc in one place and impacket in another.
- The explicit `-u/-p`/`--creds-file` loop's retry for **completely empty** nxc output (added
  in the entry below) reused the same short `timeout=40` as the first attempt (so ~80s total
  margin), while its sibling retry — for a timeout that cut `nxc` off mid-run but left *partial*
  output — already used a more generous `timeout=120`. Found live against a loaded pivot/target
  (`BR086` on a lab DC over a tunnel): the credential authenticated fine run by hand seconds
  later, but 40+40s wasn't always enough margin for nxc to even print its banner through the
  tunnel, so a genuinely valid credential could still be discarded as "no responde" before
  Fase 5d ever got to `--users`/`--shares` with it. Both retries now use the same `timeout=120`.
- Quick Wins only ever looked for next-step commands inside the exact same footprint-dict as
  the finding — but Fase 5d (credentialed) findings live in a *separate* dict from the
  anonymous-footprint dict of the same protocol (`reuse-winrm` vs `winrm`, etc. — see
  `_group_footprints_by_protocol`, already used by the HTML/Markdown renderer for exactly this
  split). Found live: the single most actionable finding in a whole report — admin access
  confirmed via WinRM (`Pwn3d!`) — showed up in Quick Wins with **no command at all**, because
  the matching `evil-winrm -i ip -u USER -p PASS` suggestion (already filled with the real
  credential, see the `_fill_cred_placeholder` entry above) lived in the sibling anonymous
  `winrm` dict, not in `reuse-winrm`. `quick_wins()` now pools next-steps across the whole
  protocol (anonymous + default-creds + provided-creds) before picking commands for a finding.
- The initial, credential-less kerbrute user count (`Kerberos: N usuario(s) AD válidos por
  kerbrute`) stayed in Quick Wins even after a later, credentialed domain enumeration produced
  the complete list from the same `ad_users.txt` (`AD (cred X): N usuarios del dominio`) —
  found live, side by side: 57 users (partial, wordlist-guessed, pre-credential) and 2901
  (complete, queried directly with a validated credential), as two separate "where to start"
  entries pointing at the same file, confusing rather than helpful. Quick Wins now drops the
  partial kerbrute entry once a complete, credentialed domain-user finding exists anywhere in
  the report — the full report itself keeps both (they're genuine, distinct findings from
  different phases), only the condensed Quick Wins view is deduplicated.
- A credential that nxc returned **completely empty output** for (a transient SMB/LDAP
  connection hiccup, common after several back-to-back calls to the same host) was silently
  recorded as "checked, invalid" — a false negative that skipped the entire credentialed
  enumeration for that protocol. Confirmed live: `nxc smb IP -u AB920 -p weasal` came back
  empty during palantir's credential-reuse step and was marked failed, yet the operator re-ran
  the exact same command moments later and it authenticated with `(Pwn3d!)`. A real auth
  failure returns text (`STATUS_LOGON_FAILURE`), so empty output specifically means nxc never
  answered. `_run_capture_retry` already existed for exactly this symptom (its own docstring
  describes it) but wasn't wired into the credential checks: `_cc_nxc` (default creds),
  `_nxc_try_cred` (the reuse chain), and the explicit `-u/-p`/`--creds-file` loop now retry on
  empty output before giving up, and say so in the step text instead of leaving a blank that
  reads like "nothing found". Seen across the same run on multiple hosts (4/4 default-cred SMB
  checks empty on one, 3/4 on another).
- Generic "USER"/"PASS" placeholders in next-step suggestions (`evil-winrm -i ip -u USER -p
  PASS`, `impacket-wmiexec DOMINIO/USER:PASS@ip`, `nxc smb ip -u USER -p PASS -x whoami`,
  `xfreerdp … /u:USER /p:PASS`, `soapy DOMINIO/USER:'PASS'@ip`) stayed unfilled even when a
  real credential had already been confirmed in the very same report — found live: WinRM
  showed a `(Pwn3d!)` admin credential in its "credenciales aportadas" findings, while the
  "Siguientes pasos" card right above it still read `-u USER -p PASS`. These placeholders are
  generated by the anonymous-footprint functions (`fp_winrm`, `fp_msrpc`, …), which run well
  before Fase 5d (`provided_creds_check`) confirms anything — and that phase writes into a
  *separate* footprint-dict per protocol, so nothing ever went back to update the earlier
  one. Every place that confirms a credential with a real login (the explicit `-u/-p`/
  `--creds-file` loop, the `-U/-P` bulk-spray loop, and the reuse-chain that retries known
  credentials against other protocols) now records it; a new `_fill_cred_placeholder` pass —
  same pattern as the existing `DOMINIO`/`NETBIOS-DEL-DC` placeholder fills — then substitutes
  it into every next-step across the whole target's report, preferring an admin/`Pwn3d!`
  credential over a merely-valid one when more than one was found. Password-only: a
  pass-the-hash credential is excluded, since none of these templates accept `-H`.
- The Kerberos "Siguientes pasos" (next-steps) list suggested the exact same AS-REP roast
  command twice, with only the trailing comment differing — found live, against a real DC.
  Whenever the AD domain is already known and `kerbrute userenum` finds valid users,
  `_kerbrute_userenum` queues an `impacket-GetNPUsers … -usersfile ad_users.txt -no-pass`
  suggestion itself ("AS-REP roast de los usuarios hallados"); `fp_kerberos` then
  unconditionally appended its own generic version of the same command ("AS-REP roast: 1
  intento por usuario YA conocido") regardless of whether one had already been queued.
  `_kerbrute_userenum` now reports back whether it already suggested the AS-REP roast, and
  `fp_kerberos` skips its own copy when it did.
- A single corrupted credential harvested from an `--lsa` dump could silently wipe out the
  *entire* "credenciales aportadas" phase for a target — found live, against a real DC/box
  pair, mid-`--resume` run. After a valid credential gets admin on SMB, palantir auto-chains
  `nxc --sam`/`--lsa` and feeds anything that looks like `usuario:secreto` in the LSA output
  back into the credential-reuse pool to retry against the other protocols. One real LSA dump
  returned a line whose "usuario" field was `INLANEFREIGHT.LOCAL\x00/tpetty` — a raw/binary
  parsing artifact, not an actual credential — and that embedded NUL byte reached
  `subprocess.run()` unfiltered once the reuse chain tried it, crashing with `ValueError:
  embedded null byte`. Because that exception wasn't caught inside `provided_creds_check`,
  it propagated all the way up and got swallowed by the generic per-phase handler, which
  discarded every footprint dict that phase had already built for that target — the valid
  credential finding, the SAM hashes, the rest of the LSA secrets, all of it — not just the
  one bad retry; the report ended up with no "credenciales aportadas" section at all for
  that host. `_pool_add` (the single choke point every discovered credential goes through
  before being replayed automatically) now rejects any user/secret containing a NUL byte
  instead of pooling it, and `provided_creds_check` no longer lets a failure inside the
  reuse-chain step discard results gathered earlier in the same phase.
- `--lsa` dump parsing was mislabelling almost every secret, losing the one that mattered.
  A real LSA dump mixes several distinct secret types on lines that all share the shape
  `a:b` — MSCache/DCC2 cached hashes (`DOMAIN/user:$DCC2$…`, crackable offline, *not* a
  password), machine-account secrets (`DOMAIN\HOST$:` Kerberos keys / `plain_password_hex` /
  SAM-format NTLM), and the genuinely valuable one: a cleartext user credential
  (`DOMAIN\user:password`, e.g. an autologon DefaultPassword or a service account). The old
  parser ran a single generic `user:secret` regex and dumped all of them into "credencial en
  texto claro" findings *and* the reuse pool — so DCC2 hash strings got replayed as if they
  were passwords (which is also what dragged the NUL-poisoned username into `subprocess`),
  while the actual cleartext credential was buried in the same undifferentiated pile. The
  parser now returns each secret type separately: DCC2 → reported as crackable (`hashcat -m
  2100`), machine-account secrets → reported as such (silver-ticket / machine PtH material),
  and only a real cleartext credential is pooled for automatic reuse — with its `DOMAIN\`
  prefix stripped so nxc actually accepts it on replay (nxc infers the domain from the
  target; the literal prefix makes the login fail). Verified against the exact real dump that
  surfaced this.
- SAM dump auto-replay was spamming disabled built-in accounts and crying wolf over empty
  passwords. After a Pwn3d!, palantir auto-dumps SAM and fed every non-machine account's NT
  hash into the reuse pool — including `Guest`/`DefaultAccount` (whose hash is the empty-
  password constant) and `WDAGUtilityAccount`, all disabled by default — so a single box
  produced a burst of pointless pass-the-hash attempts across winrm/wmi/smb/rdp (seen live in
  `commands.log`). It also emitted a `critica` "login directo sin contraseña" for every
  built-in that dumped with a blank hash, i.e. two false criticals on essentially every
  modern Windows host. Now the empty-password hash and the well-known disabled built-in RIDs
  (501/503/504) are kept in the report (still visible for manual use) but excluded from the
  automatic reuse chain, and a blank hash on those built-ins is reported as `info`
  ("integrada, normalmente deshabilitada") rather than a false `critica`.
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
