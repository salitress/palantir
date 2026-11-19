# Contributing to palantir

Thanks for considering a contribution. `palantir.py` is a single-file Python
script by design — no package, no build step. This doc covers the project's
internal layout and the quickest way to add something new.

Note: the codebase itself (comments, CLI output, HTML/Markdown reports) is
written in **Spanish** — that's intentional and part of the tool's character,
not an oversight. Pull requests are welcome in either language; keep new code
comments consistent with the surrounding Spanish style unless you're
discussing with maintainers in an issue/PR description.

## Design philosophy

- **Read-only, default credentials only.** Every footprinting step is either a
  passive read or a single login attempt with a known default credential
  (null session, `guest`, `Administrator` with no password, `sa` with no
  password, etc.) — never brute force, never a write to the target.
- **Nothing exploits itself.** Confirming a vulnerability (Zerologon, noPac,
  AD CS templates, DCSync rights...) is fine; *weaponizing* it (resetting a
  machine password, requesting a certificate, a full NTDS dump) is always
  left as a manual next step with the exact command, never chained
  automatically. This is also what keeps the tool usable under exam rules
  that ban automated exploitation (OSCP included).
- **Stdlib core, optional tools.** The core (`subprocess`, `socket`,
  `ftplib`, `smtplib`, `urllib`, `xml.etree`, `json`...) has zero third-party
  dependencies. Every external tool (`nmap`, `nxc`, `ffuf`, `searchsploit`,
  `certipy`...) is detected at runtime with `have()`/`*_bin()` helpers; if one
  is missing, that service's checks are skipped and the rest of the run
  continues.
- **Secrets never touch argv.** A password/hash goes through a 0600 temp file
  or an environment variable wherever the target tool supports it; it's
  masked in whatever gets persisted (report, `commands.log`). See the
  `_creds_enum`/`provided_creds_check` functions for the established pattern.
- **Every command explains itself.** Each step is printed with a short *why*
  (`↳ por qué:` on screen, same text in the HTML report) — this is meant to
  double as a learning tool, not just a scanner.

## Code layout

| Area | Functions |
|---|---|
| Nmap phases | `fast_ports`, `deep_scan`, `udp_scan`, `parse_nmap_xml`, `scan_type()`, `_nmap_run` |
| `--resume` (skip phases, not just nmap) | `_ports_signature`, `_load_prev_findings`, `_resume_reuse_ok` |
| Web/vhost fuzzing | `run_ffuf`, `fuzz_dirs`, `fuzz_vhost`, `primary_web_ports`/`_mirror_map` |
| Per-protocol footprinting | `fp_ftp`, `fp_smb`, `fp_nfs`, `fp_dns`, `fp_snmp`, `fp_kerberos`, `fp_docker`, ... + `fp_generic` (NSE + next-steps only); web split into `fp_web_fast` (seconds) and `fp_web_slow` (nikto/nuclei/wpscan/joomscan/katana, opt-in, minutes) |
| Default credentials (phase 5c) | `creds_check` + `_CC_DISPATCH` + `cc_*`; DB in `DEFAULT_CREDS`/`SNMP_COMMUNITIES`/`IPMI_CREDS` |
| Provided credentials / reuse (phase 5d) | `_user_pass_combos`, `parse_provided_creds`, `confirm_creds_spray`, `provided_creds_check`, `_dump_sam_lsa`, `_creds_enum` |
| External binaries outside apt | `nxc_bin`, `_crtsh_bin`, `_impacket_suggest_bin`, `_bin_with_sudo_fallback` |
| Reports | `build_html`, `build_markdown`, `quick_wins`, `write_reports`, `write_index` |
| Multi-target / parallel | `expand_targets`, `target_folders`, `run_one`/`_run_one_guarded`, `main` |
| Self-test (no network) | `selftest` + `SELFTEST_XML` |

Every footprint function returns a dict built with `_fp(proto, title, ports)`:

```python
{"proto", "title", "ports", "steps", "findings", "next", "missing"}
```

- `steps`: list of `{"cmd", "ok", "output", "note"}`, added via `_step(...)`.
- `findings`: list of `(severity, text)` — severities are `critica` < `alta`
  < `media` < `info` (see `SEV_ORDER`).
- `next`: ready-to-copy follow-up commands.
- `missing`: tools that were needed but not installed.

Both the anonymous footprint and `creds_check`/`provided_creds_check` return
lists of these dicts, so they render (`render_footprint`) and export
(`build_html`/`build_markdown`/JSON) the same way without extra plumbing.

## Adding a new protocol

1. **`classify(p)`** — add the port/service name, return a new id (e.g. `"xyz"`).
2. Write **`fp_xyz(ip, ports, services, host, deep)`** returning an `_fp(...)` dict:
   - One `_step(res, cmd, ok, output, note=...)` per command (use
     `run_capture`; check `have("tool")` first and append to
     `res["missing"]` if it's absent).
   - `res["findings"].append((severity, text))` for anything worth flagging.
   - `res["next"].append("command ...")` for follow-ups — always at least one.
   - If all you need is NSE output + suggestions, `fp_generic(...)` already
     covers that case.
3. Add the `elif proto == "xyz":` branch in **`footprint_services`**.
4. If it has known default credentials, add them to `DEFAULT_CREDS` and a
   `cc_xyz` entry in `_CC_DISPATCH` (reuse `_cc_nxc` if `nxc` already speaks
   that protocol).
5. Add assertions to **`selftest`** (at least for `classify`), run
   `python3 palantir.py --selftest`.

## Conventions

- **Read-only.** Secrets never go on a subprocess's command line — use an env
  var (`run_capture(..., env=...)`, see MySQL/PostgreSQL/Redis/IPMI) if the
  tool supports it, or a `0600` temp file deleted in a `finally` block
  otherwise (see `provided_creds_check`/nxc).
- Confirm access for real (don't stop at "it connected") to keep false
  positives down.
- Any value that came **from the target** and ends up in a suggested `next`
  command (something the operator will copy/paste) must go through
  `shlex.quote()` — never hand-quoted (see the NFS/SMB-spider/LDAP steps).

## Testing

- `python3 palantir.py --selftest` runs every pure-function test (parsers,
  classification, HTML/Markdown generation) without touching the network.
  Keep it green; add assertions whenever you touch non-trivial logic.
- `.github/workflows/selftest.yml` runs `py_compile` + `--selftest` on every
  push and PR.
- Testing against a real target requires an authorized lab (HTB, a CPTS/OSCP
  practice box, an engagement you have written permission for). Never run
  this against anything you don't have explicit authorization to test.

## Pull requests

- Keep `--selftest` green; add test cases for new pure functions/parsers.
- Keep the read-only / no-auto-exploit philosophy above — if a change would
  cross that line, open an issue to discuss it first.
- One logical change per PR is easier to review than a grab-bag.

## Versioning

Releases follow [Semantic Versioning](https://semver.org/) (`vMAJOR.MINOR.PATCH`):

- **MAJOR** — a flag is removed/renamed, a default behavior changes in a way
  that could surprise an existing user (e.g. a phase that used to run by
  default now doesn't), or the report/JSON format changes incompatibly.
- **MINOR** — a new flag, a new protocol, or a new check added without
  changing any existing behavior.
- **PATCH** — a bugfix, a wording/report fix, or anything else that doesn't
  change the CLI surface.

Each release is tagged `vX.Y.Z` on `main` and gets an entry in
[CHANGELOG.md](CHANGELOG.md).
