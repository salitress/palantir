---
name: Bug report
about: Something palantir does is wrong, crashes, or gives a false positive/negative
title: ''
labels: bug
assignees: ''
---

**What happened**
A clear description of the bug — a crash, a wrong finding, a false
positive/negative, a command that doesn't do what the `note`/`↳ por qué`
says it does, etc.

**Command used**
```
sudo ./palantir.py <sanitized target> <the flags you used>
```
Redact the real target IP/hostname and any real credentials if this is
against a client/exam environment — `10.0.0.1`/`example.com` is fine.

**Expected vs actual**
What you expected palantir to detect/do, and what it actually detected/did.

**Relevant output**
Paste the relevant snippet from the terminal, `report.html`/`report.md`, or
`findings.json` — not the whole file unless it's small. Again, redact real
targets/credentials.

**Environment**
- `palantir.py --selftest` passes? (yes/no)
- OS / Kali version:
- Relevant external tool + version (e.g. `nxc --version`), if the bug looks
  tied to one:

**Target context (if relevant)**
What kind of target this was (HTB box, CPTS/OSCP lab, a real engagement) and
what the OS/service actually is, if you know it — this often explains a
false positive/negative that's specific to one version of a service.
