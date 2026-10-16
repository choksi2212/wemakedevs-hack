# Contributing to SEVER

SEVER is a hackathon project, but the bar is production-honesty: every claim in
the docs traces to a receipt, and nothing ships on belief. Keep that bar.

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
- **Mermaid diagrams**: any ```` ```mermaid ```` block you touch must pass a
  `mermaid.parse()` harness pre-commit (see the docs/README receipts-first rule).
- **Honesty rules**: verdicts are re-queried claims, proposals are always real
  edges, the human gate passes only on literal `True` — don't weaken these for
  convenience; tests pin them.
- **Docs discipline**: numbers in `docs/` and `README.md` cite
  `docs/receipts/` artifacts. If you change a number, the receipt comes first.

## PR conventions

Small, single-purpose diffs; describe what a receipt proves, not what you hope.
The repo is MIT — see `LICENSE`.
