# audit5/api-matrix — live API conformance harness

Owner-authorized input-matrix conformance sweep for the SEVER console,
run 2026-10-16 against the LIVE deployment (https://sever-console.onrender.com,
FalkorDB Cloud `sever_demo`) and against a disposable own instance on the
ryzen host (branch-tip code, ports 8305/8306, graph key `sever_audit5_apimatrix`
— deleted after the run).

## What it asserts (the documented contract)

`422 schema / 400 vocabulary+estate / 403 gate / 413 body cap / 503 only for
engine stalls`, per `sever/console/app.py` + `sever/console/schemas.py`:
malformed JSON, wrong content-types, missing/empty/100KB fields, lone
surrogates, truthy non-bool `approved` (1, 1.0, "true", "yes", "on", "1",
nested, array), duplicate JSON keys (last-wins, fail-closed), unknown kinds,
unknown-but-schema-valid rels (`generic_all` -> 400 vocabulary), ghost
principles (400 estate), self-grants, SSRF-shaped fields (client error,
never fetched), body cap boundary (<=1MB reaches the schema/gate;
1,000,001B -> 413; chunked over-cap rejected 400-or-413, never buffered —
see tests/test_body_size_limit.py), the `/api/plan` + `/api/plan/execute`
gate (403 without approval, gate BEFORE any rel/estate oracle), per-step
re-measure receipts, drift-stop on tampered projections, and the
`/api/receipts` ledger (append-only, parseable, ordered, concurrent
cross-process writers, readable during an engine outage).

## Files

- `live_matrix.py` — rejection matrix + no-op/idempotent mutations against a
  live deployment (mutations owner-authorized; nothing destructive — no real
  edge is ever removed). `SEVER_AUDIT_BASE` overrides the target,
  `python live_matrix.py <out.jsonl>`.
- `own_matrix.py` — destructive conformance (real findings/cuts, full plan
  execution, drift-stop, cross-process ledger storm, induced engine stall ->
  503 + honest `cut_failed` ledger record). Point it at a disposable graph
  (`sever_audit5_*`) — it mutates and collapses the estate.
- `run_own_ryzen.ps1` — one-SSH-session driver: clean slate, boot two
  consoles, poll readiness, run `own_matrix.py`, stop consoles, delete the
  graph + CaseLog files, verify engine health. Engine "stall" is induced by
  suspending (NtSuspendProcess) the FalkorDB process — never by killing it —
  with `SEVER_FALKOR_SOCKET_TIMEOUT=3` so 503s fire in ~3s.

## Verdict (2026-10-16, both runs)

**Zero contract deviations.** 96 live cases + 86 own-instance cases:
0x500, 0x503 with a healthy engine (503 only under induced stall, every
response then clean JSON), exact 413 boundary at 1MB+1 on both hosts,
gate-first ordering on every gated endpoint, drift-stop verified with real
and tampered projections, ledger append-only (live 48->89, own 5->109, both
prefix-preserved and ordered). Every behavior observed was already pinned by
the repo's own tests (test_console*.py, test_body_size_limit.py,
test_planning.py) — no fixes required, no new regressions needed.
