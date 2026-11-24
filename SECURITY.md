# Security Policy

## Scope

This policy covers vulnerabilities **in `palantir.py` itself** — the tool's
own code (for example: command injection via an unsanitized value, a path
traversal in report writing, a secret ending up somewhere it shouldn't,
unsafe handling of target-controlled data in a suggested `next` command).

It does **not** cover:

- Vulnerabilities `palantir` *finds* in a target you scanned — those are
  yours to report to that target's owner, not to this project.
- Misuse of `palantir` against systems you don't have authorization to
  test. See [README.md](README.md)'s authorized-use expectation and
  [CONTRIBUTING.md](CONTRIBUTING.md) — `palantir` is built to stay read-only
  and non-destructive by design, but it's still a pentesting tool, and
  running it against anything without written permission is on you, not on
  a flaw in the project.

## Supported Versions

There's no formal LTS. Only the **latest tagged release** on
[`main`](https://github.com/salitress/palantir/releases/latest) is
supported — please update before reporting, in case it's already fixed.

## Reporting a Vulnerability

Please **don't open a public issue** for a security report — open it as a
[private security advisory](https://github.com/salitress/palantir/security/advisories/new)
instead (GitHub's "Report a vulnerability" form under this repo's Security
tab). That keeps it confidential between you and the maintainer until a fix
ships.

Include, if you can:

- The affected function/flag and a minimal repro (a crafted hostname,
  finding text, or similar — whatever triggers it).
- What you'd expect instead.
- Whether it requires a specific flag (`--crawl`, `-u`/`-p`, etc.) to reach.

You should get an initial response within a few days. There's no bug
bounty — this is a personal project — but you'll be credited in the fix's
commit/changelog entry unless you ask not to be.
