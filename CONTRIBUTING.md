# Contributing to SEVER

SEVER is a hackathon project, but the bar is production-honesty: every claim in
the docs traces to a receipt, and nothing ships on belief. Keep that bar.

## Rules NOTE

The official rules, schedule, and prize breakdown may be updated before the
hackathon; any change is announced through the WeMakeDevs and FalkorDB
community channels. Re-verify
<https://www.wemakedevs.org/hackathons/falkordb/rules> (and the event Discord)
before submission — `docs/RESEARCH_FALKORDB_ECOSYSTEM.md` §0 is a dated
snapshot, not current truth.

## Setup

Follow [README §9](README.md#9-reproduce-everything) — `docker compose up -d`
(FalkorDB 6.0.0), download the SpecterOps sample zips, then
`pip install -e ".[dev,console,memory,agent]"`. All engine knobs are documented
in [`.env.example`](.env.example) (copy it to `.env` if you need non-defaults;
real environment variables always win).

## Before you push

```bash
python -m pytest                # DB-free suite must be green (engine tests skip cleanly)
python -m pytest tests/test_live.py   # with the engine up, for graph-port changes
```

- **DB-free green is the gate**: 0 failures; engine suites skip without docker.
- **No receipt edits**: `docs/receipts/` is append-only captured evidence. New
  claim? Capture a new receipt (the scripts write them) — never edit an old one.
- **Mermaid diagrams**: validate any ```` ```mermaid ```` block you touch
  before pushing — render it in the GitHub preview (or run `mermaid.parse()`
  locally, e.g. via mermaid.cli); a broken diagram must never land.
- **Honesty rules**: verdicts are re-queried claims, proposals are always real
  edges, the human gate passes only on literal `True` — don't weaken these for
  convenience; tests pin them.
- **Docs discipline**: numbers in `docs/` and `README.md` cite
  `docs/receipts/` artifacts. If you change a number, the receipt comes first.

## PR conventions

Small, single-purpose diffs; describe what a receipt proves, not what you hope.
The repo is MIT — see `LICENSE`.
