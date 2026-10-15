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
**10 shortest attack paths to the crown jewels** (GMSA password-read
kill chain annotated hop-by-hop with ATT&CK technique labels).

**0:50–1:10 — The live mutation.** Finding F-003: a new `GENERIC_ALL` ACE is
granted mid-session — the edge appears **live** on the canvas; the agent
re-scores all paths immediately. (Ties to FalkorDB sub-ms writes.)

**1:10–2:20 — The interdiction cascade.** Agent proposes the top-frequency
edge (`GMSA_SHS_PWD -[READ_GMSAPASSWORD]-> GMSA_SHS8$`). **Human gate:
APPROVED.** Cut #1 executes → re-query → reachability **1→1 DEGRADED (4.84ms)** —
honest verdict: the top-frequency edge wasn't the real chokepoint. Agent
re-ranks → proposes the remaining GMSA password-read edge. **APPROVED** →
cut #2 → reachability **1→0 COLLAPSED, re-query 2.98ms**, receipts printed:
before/after, PROFILE timing, approvals, timestamps.
(As-logged in docs/receipts_live_sever_demo.json — cut #1 verdict `degraded`,
cut #2 verdict `collapsed`.)

**2:20–2:40 — Scale wall.** Tenant switch: `sever_tenant002` is a completely
different org (disjoint SIDs) — instant graph swap, native multi-tenancy.
Then the generator: hundreds of tenant graphs in ONE FalkorDB instance,
latency-flat. (FalkorDB's signature 10K-graphs-per-instance story, made real.)

**2:40–3:00 — Provenance & close.** Receipts JSON on screen; exact Cypher from
`docs/CYPHER.md`; commit history visible (all work inside the event window);
AI-assist disclosure; exact repro (`docker compose up -d` for the engine,
then `python scripts/rehearse.py`).

## Fallback ladder (pre-recorded segments)

1. Live deploy (FalkorDB Cloud w/ heartbeat) → 2. Self-host Docker on the build
host (`docker compose up -d`) → 3. the pre-recorded backup take at
`out/demo/sever_demo.webm`, captured headless from the live console by
`python scripts/demo_video.py`. The engine never changes between tiers —
there is no second engine to fall back on. Every take runs on live FalkorDB
(remove it and the product breaks; that's the point).

---

## LIVE-VERIFIED NUMBERS (Oct 15, measured on the build host — use these)

- Hero beat: breach → 5 canonical paths to 5 crown jewels → gated cut rounds →
  reachability 1 → 1 DEGRADED → 1 → 0 **COLLAPSED, re-query 2.98ms**
- Console arc (HTTP E2E): breach → proposal → ONE gated cut → **1 → 0
  COLLAPSED** — 3.46ms on the fastest of five live takes (every take logged in
  `out/cases/sever_demo.jsonl`)
- T2 cross-process: fresh process resumes from FalkorDBSaver case memory →
  "triage remembered" → gated cut → **1 → 0 in 2.01ms**
- Hybrid: cloud identity → bridge pivot → Domain Admins; bridge severed →
  **1 → 0 in 2.76ms**
- Scale wall: 300 tenants / 444,000 nodes / 3.7M edges in **1.29 GiB**, queries
  flat (median 3.66ms, p95 4.11ms)
- PROFILE receipt: docs/receipts/profile.txt (0.83ms in-engine on the tenant)

## CONSOLE CLICK-PATH (record this)

Bring-up (copy-paste): `docker compose up -d` (engine) ·
`uvicorn sever.console.app:app --host 0.0.0.0 --port 8000` (console)

1. Open `http://<build-host>:8000/?static=1` — estate panel: 1,480 nodes, 5
   jewels (`?static=1` freezes the 15s auto-refresh for a clean take;
   `scripts/demo_video.py` loads it automatically)
2. Click **"▶ simulate breach (mark owned)"** → red reachability **1**, 10
   paths light up with hop-by-hop rel types, ATT&CK narration banner
   (*T1078.002 Valid Accounts: Domain Accounts*)
3. Click **"▶ simulate new ACE grant (live mutation)"** → the graph mutates
   live (a `GENERIC_ALL` edge onto the GMSA group), agent re-scores
4. Click **APPROVE CUT** on the top proposal — `DF-MS-SHS -[MEMBER_OF]->
   GMSA_SHS_PWD`, on 10 of 10 paths — the verdict banner prints the receipt
   (reachability before → after, re-query ms, verdict). Live takes collapsed
   on the first approved cut; if a take lands DEGRADED, approve the
   re-ranked proposal until the banner reads **COLLAPSED**
5. Show the receipts ledger scrolling — every action, timestamped (last 8
   in the panel; full ledger in `out/cases/sever_demo.jsonl`)
6. Cut to the FalkorDB browser UI (:3000) for the raw graph, then the scale
   wall receipts (docs/receipts/scale_wall.json)

Backup take, headless from the live console:
`python scripts/demo_video.py --console http://127.0.0.1:8000 --out out/demo`
writes `out/demo/sever_demo.webm` (webm — Playwright's native container, not
mp4) plus storyboard screenshots in the same directory.
