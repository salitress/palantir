---
name: Feature request
about: A protocol/check/flag palantir doesn't cover yet
title: ''
labels: enhancement
assignees: ''
---

**What's missing**
What palantir doesn't detect/do today, and why it'd be useful — ideally
with a real case where you hit the gap (a box/lab where this would have
mattered).

**How would it fit the project's design**
`palantir` is read-only and non-destructive by design (see
[CONTRIBUTING.md](../../CONTRIBUTING.md#design-philosophy)): it detects and
suggests a copy-pasteable next step, it never chains an active/exploitation
step automatically. If what you're asking for would cross that line, say so
— it might still be worth adding as a **suggested** `next` command instead
of something palantir runs itself.

**Proposed command/check**
If you already know the tool/flag/NSE script that would do this, name it —
e.g. "run `nmap --script <x>` when port Y is open" or "add `-M <module>` to
the nxc call for protocol Z".

**Alternatives considered**
Anything else that could cover the same gap, and why this is better.
