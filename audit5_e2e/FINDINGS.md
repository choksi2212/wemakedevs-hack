# audit5/live-e2e — LIVE E2E journey audit findings & fixes

Branch `audit5/live-e2e` (off origin/main a2688f3). Live target:
https://sever-console.onrender.com (engine: FalkorDB Cloud ap-south-1, estate
`sever_demo` 1,480n/12,450e). Browser: Playwright headless Chromium on the
ryzen host, viewport 1440x900, screenshots per step, zero-tolerance JS
console-error listener. Driver: `audit5_e2e/audit5_e2e_driver.py`
(parts A/B), evidence in `audit5_e2e/resultsA*` + `audit5_e2e/fixresults/`.

## Journey coverage (DEMO_SCRIPT.md click-path, all verified live)

Load → "Simulate breach finding" → "Grant new ACE (live mutation)" →
refresh toggle (pause/resume) → APPROVE CUT → CONFIRM CUT gate (armed in
0.032s, survives the 15s auto-refresh tick, Escape disarms, confirm executes
with INTERDICTION RECEIPT banner) → reload mid-flow → "Plan k-cut sequence"
(APPROVE PLAN → cancel restores APPROVE PLAN) → CONFIRM PLAN → re-plan →
execute-to-completion → collapse via gated single cuts → receipts ledger.
Button labels, narration (T1078.002 / T1098), verdict copy (degraded/collapsed)
and estate metrics all match `docs/DEMO_SCRIPT.md` beats 1-6.

## Defects found (live evidence; screenshots referenced from the runs)

1. **UI copy defect — proxy HTML error pages leaked into the banner.**
   `api()` surfaced any non-JSON body via `text.slice(0, 120)`; during the
   live 502 storm the operator saw `finding failed: <!DOCTYPE html> <html
   lang="en"> …` (Render's branded error page) in the banner — reproduced 5+
   times across runs (`audit5_e2e/resultsA/e2e_results_A.json`,
   `A1_breach_retry` / `A2_grant_retry` steps; shot 03_breach_result
   context). FIXED: HTML bodies now render as
   `server error <status> (HTML error page)`.
2. **Server defect — GET /api/receipts shipped the whole append-only ledger.**
   Every `/api/state` poll appends a ledger line, so the only full-file route
   grew without bound; on the live deployment the route went hard-down
   (HTTP 502 with Render's 223,038-byte error page, 4/4 attempts 06:15Z;
   empty-body variant before that) while `/api/state` kept answering, and the
   container eventually recycled with a wiped ephemeral ledger at 06:28Z
   (receipts 200 again at 2,095 B and growing 7 KB/round under load).
   FIXED: endpoint returns the newest `limit` (default 200, cap 5000)
   events; UI renders the newest 40. Full file stays on disk for forensics.
3. **UI state defect — a receipts-only failure flipped the whole-engine chip.**
   `refresh()` caught any of paths/proposal/receipts failing as "engine
   unreachable" while `/api/state` (and paths/proposals) kept flowing —
   the chip lied for minutes at a time. FIXED: the receipts fetch has its
   own failure lane; the card degrades to
   `ledger unavailable — <reason>` and the engine chip stays green.
4. **UI copy defect — plan card printed the literal `null` for unmeasured
   benign usage.** `benign_usage: null` is the documented "not measured"
   shape (fast-path proposal, `rank_cut_candidates` contract;
   `tests/test_agent.py` pins it) but `renderPlan()` concatenated it raw:
   `benign null`. The proposal card already hid nulls. FIXED:
   `benign not measured`.
5. **Gate-integrity gap — CONFIRM PLAN stayed clickable mid-execution.**
   `executeConfirm` (single cut) disables its buttons for the flight;
   `executePlan` did not — a double-press during the multi-second
   `/api/plan/execute` could fire a second execution. FIXED: both
   CONFIRM/CANCEL disable immediately at execute start.
6. **Availability findings (not UI bugs — recorded, no code change here):**
   the single uvicorn worker runs blocking engine I/O inside `async def`
   handlers, so concurrent audit traffic (six audit5 agents + demo UIs
   polling every 15s) head-of-line-blocks the loop: sustained 502 storms
   (98 API calls in run 1: 27/48 `/api/state` 502s), 200-with-empty-body
   responses (the original incident signature — also seen on `GET /`,
   i.e. a blank page), and 22.7s `/api/state` latencies. The a2688f3 UI
   fix held: zero uncaught JS page errors, no "Unexpected end of JSON
   input" anywhere across all runs.

## Tests

- `tests/test_console_resilience.py` (+2, DB-free): receipts tail bounded
  (default 200 newest-last, `?limit` clamps, small ledgers ship in full).
- `tests/test_console_ui.py` (+4, DB-free static): HTML-error-page guard,
  receipts-lane degradation copy, benign-not-measured, CONFIRM PLAN disable.
- `tests/test_dom_escape_coverage.py` (conscious extension): 9 innerHTML
  sinks (the receipts degraded line), receipts render sink re-pinned,
  `recErr.message` added to the untrusted set.
- Full DB-free suite green locally (exit 0, engine-gated tests skipped via
  dead port). Browser-verified on the ryzen against a booted instance of
  this branch (`audit5_e2e/fix_verify.py` + `fixresults/`): all F1-F5
  checks PASS with screenshots fix01-fix06.
