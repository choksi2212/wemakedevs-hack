# SEVER — 3-Minute Demo Script (video storyboard)

**Thesis:** attack-path tools stop at advice. SEVER closes the loop — ranked cut →
human gate → live re-query → before/after receipts — per-tenant, in milliseconds.

**Environment disclosure (shown on screen at 0:00):** simulated identity estate
built from the official BloodHound CE sample data (Apache-2.0, SpecterOps);
findings are a labeled breach-timeline replay. All data public/synthetic.

## Timeline

**0:00–0:20 — The estate.** FalkorDB browser (:3000) shows the `sever_demo`
tenant graph: 1,480 nodes / 12,450 edges ingested in seconds. Headline metric
panel: **5 crown jewels** across 3 domains; reachability 0 (nothing owned yet).

**0:20–0:50 — The breach.** Finding F-001 lands (infostealer dump —
*T1078.002*): `T1_TONYMONTANA@PHANTOM.CORP` marked owned. The graph lights up:
**5 canonical attack paths to the 5 crown jewels** (GMSA password-read
kill chain annotated hop-by-hop with ATT&CK technique labels).

**0:50–1:10 — The live mutation.** Finding F-003: a new `GENERIC_ALL` ACE is
granted mid-session — the edge appears **live** on the canvas; the agent
re-scores all paths immediately. (The canonical path query itself runs
~0.83 ms in-engine — `docs/receipts/profile.txt`.)

**1:10–2:20 — The interdiction cascade.** Agent proposes the top-frequency
edge: `GMSA_SHS_PWD -[READ_GMSAPASSWORD]-> S-…-2138`. **Human gate:
APPROVED.** Cut #1 executes → re-query → reachability **1→1 DEGRADED
(4.84ms)** — honest verdict: the top-frequency edge wasn't the chokepoint; a
parallel GMSA password-read still carries the paths. Agent re-ranks →
proposes the remaining `READ_GMSAPASSWORD` out of `GMSA_SHS_PWD`
(`S-…-2102 -[READ_GMSAPASSWORD]-> S-…-2186`; every recorded proposal edge
lies on 5 of 5 paths). **APPROVED** → cut #2 → reachability **1→0 COLLAPSED,
re-query 2.28ms**, receipts printed: before/after, re-query timing,
approvals, timestamps. (As logged in
[`docs/receipts_live_sever_demo.json`](receipts_live_sever_demo.json) —
cut #1 verdict `degraded`, cut #2 verdict `collapsed`.)

**2:20–2:40 — Scale wall.** Tenant switch: `sever_tenant002` is a completely
different org (disjoint SIDs) — instant graph swap, native multi-tenancy.
Then the generator: hundreds of tenant graphs in ONE FalkorDB instance,
latency-flat. (FalkorDB's signature 10K-graphs-per-instance story, made real.)

**2:40–3:00 — Provenance & close.** Receipts JSON on screen; exact Cypher from
`docs/CYPHER.md`; commit history visible (all work inside the event window);
AI-assist disclosure; one-command repro (`python scripts/rehearse.py`).

## Fallback ladder (pre-recorded segments)

1. Live deploy (FalkorDB Cloud w/ heartbeat) → 2. Self-host Docker on the build
host → 3. `scripts/rehearse.py` terminal recording — the same live-engine
beats in one command. There is no offline double anywhere in the product:
every rung runs the real engine.

---

## LIVE-VERIFIED NUMBERS (Oct 15, measured on the build host — use these)

- Hero beat: breach → 5 canonical paths to 5 crown jewels → gated cut rounds →
  reachability 1 → 1 DEGRADED → 1 → 0 **COLLAPSED, re-query 2.28ms**
- Console arc (HTTP E2E): breach → proposal → ONE gated cut → **1 → 0** —
  asserted over HTTP by
  `tests/test_console.py::test_approved_cut_collapses_via_console`
  (the cut receipt carries the re-query time)
- T2 cross-process: fresh process resumes from FalkorDBSaver case memory →
  "triage remembered" → gated cut → **1 → 0 in 2.47ms**
- Hybrid: cloud identity → bridge pivot → Domain Admins; bridge severed →
  **1 → 0 in 3.0ms**
- Scale wall: 300 tenants / 444,000 nodes / 3.74M edges in **1.59 GiB**, queries
  flat (median 4.67ms, p95 4.81ms)
- PROFILE receipt: docs/receipts/profile.txt (0.83ms in-engine on the tenant)

## CONSOLE CLICK-PATH (record this)

1. Open the console (build host :8000) — estate panel: 1,480 nodes, 5 jewels
2. Click "simulate breach" → red reachability **1**, paths light up with
   hop-by-hop rel types, ATT&CK narration banner
3. Click "simulate new ACE grant" → the graph mutates live, agent re-scores
4. Click **APPROVE CUT**, then **CONFIRM CUT** (the two-step gate) on the top
   proposal → verdict banner (DEGRADED keeps the story honest); approve +
   confirm the re-ranked proposal → **COLLAPSED**
5. Show the receipts ledger scrolling — every action, timestamped
6. Cut to the FalkorDB browser UI (:3000) for the raw graph, then the scale
   wall receipts (docs/receipts/scale_wall.json)

The Playwright backup take lives in `out/demo/sever_demo.webm` (recorded from
the live console with `scripts/demo_video.py`).
