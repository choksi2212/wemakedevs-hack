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
never fetched), body cap boundary (a 1,000,000B valid cut reaches the
schema/gate -> 403; 1,000,001B -> 413; chunked over-cap -> 413 on the real
uvicorn stack — FastAPI's TestClient surfaces the same aborted read as its
own 400, which is why tests/test_body_size_limit.py pins `in (400, 413)`),
the `/api/plan` + `/api/plan/execute`
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
  503 + honest `cut_failed` ledger record). Not configurable in-script: the
  graph key (`sever_audit5_apimatrix`) and ports A/B (8305/8306) are fixed
  by `run_own_ryzen.ps1`'s environment — run it via the runbook against a
  disposable graph, never an estate you care about. Phase 7 (induced stall)
  is **Windows-only**: netstat/tasklist + NtSuspendProcess; on other
  platforms it records one honest skip line and the remaining phases still
  run.
- `run_own_ryzen.ps1` — one-SSH-session driver: clean slate, boot two
  consoles, poll readiness, run `own_matrix.py`, stop consoles, delete the
  graph + CaseLog files, verify engine health. Engine "stall" is induced by
  suspending (NtSuspendProcess) the FalkorDB process — never by killing it —
  with `SEVER_FALKOR_SOCKET_TIMEOUT=3` so 503s fire in ~3s. Boot->run->stop
  is wrapped in try/finally so a failed readiness poll cannot orphan the
  uvicorn processes.

## Verdict — as captured 2026-10-16 on the PRE-audit5 console; scope honestly

The 2026-10-16 verdict ("Zero contract deviations. 96 live cases + 86
own-instance cases ... ledger append-only (live 48->89, own 5->109)") was
captured against the pre-audit5 console, which logged `/api/state` on every
poll. The shipped console logs state **only when the estate key CHANGES**
(audit5, `sever/console/app.py`), and the harness was fixed post-audit
(H14/H15/M33/M34/M35/M36) to match that behavior — so the 2026-10-16 case
counts, the per-poll ledger counts (80 state lines; live 48->89; own
5->109) and the strict-422 body-cap expectations are NOT reproducible by
the fixed harness, by design. What a fresh run of the FIXED harness
produces:

- `live_matrix.py`: 94 unconditional check cases + 1 security-headers
  record = **95 records** when `/api/paths` answers no paths (the live
  estate held no owned principal at the 2026-10-18 spot-check,
  reachability 0); **97 records** when a real hop target resolves (the two
  target-dependent vocabulary cases run).
- `own_matrix.py`: 85 unconditional records + N relight records (N = the
  executed plan's steps, 1-3) + the Windows stall lane (6 records; one
  skip record elsewhere) = **OWN-INSTANCE TOTAL of 86-88 records** on the
  documented Windows runbook. The phase-6 storm delta is **+30** ledger
  entries (one line per accepted finding post: identical state polls are
  guaranteed non-writes under change-only logging, hostile 422s write
  nothing).

Post-fix expectations that differ from the 2026-10-16 captures: the two
body-cap boundary cases are exact-size (1,000,000B valid cut -> 403 gate;
1,000,001B -> 413); the 999,999B/1,000,000B sized bodies are VALID cuts
(extras dropped by the schema) so they answer 403, not 422; ghost plan
projections are derived from the live reachability read, not hardcoded
1/0. Regenerate both runs against the current console to refresh this
verdict — the script headers carry the per-case contracts.
