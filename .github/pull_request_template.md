## What this does

A short description of the change — the bug it fixes, or the
protocol/check/flag it adds.

## Why

The real case that motivated it (a finding/false-positive you hit against a
real lab or engagement), or the gap it closes. Link an issue if there is
one.

## Testing

- [ ] `python3 palantir.py --selftest` passes
- [ ] Added/updated `--selftest` assertions for the new logic (pure-function
      parsers get a direct test; anything touching the network is mocked —
      see existing examples in `selftest()`)
- [ ] If this changes CLI output/flags, `--help` output and
      `README.md`/`README.es.md` were updated to match

## Design checklist

- [ ] Stays read-only / non-destructive (detect-and-suggest, never an
      automatic active/exploitation step — see
      [CONTRIBUTING.md](../CONTRIBUTING.md#design-philosophy))
- [ ] Any secret (password/hash) never ends up on a subprocess's argv, and is
      masked in what gets persisted (report, `commands.log`) unless
      `--hide-secrets` says otherwise
- [ ] Any target-controlled value that ends up in a suggested `next` command
      goes through `shlex.quote()`

## Notes for the reviewer

Anything that needs a second look — an edge case you're not 100% sure about,
a real run's output you verified this against, etc.
