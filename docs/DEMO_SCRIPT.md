# SEVER — 3-Minute Demo Script (video storyboard)

**Thesis:** attack-path tools stop at advice. SEVER closes the loop — ranked cut →
human gate → live re-query → before/after receipts — per-tenant, in milliseconds.

**Environment disclosure (shown on screen at 0:00):** simulated identity estate
built from the official BloodHound CE sample data (Apache-2.0, SpecterOps);
findings are a labeled breach-timeline replay. All data public/synthetic.

## Timeline

**0:00–0:20 — The estate.** FalkorDB browser (:3000) shows the `sever_demo`
tenant graph: 1,480 nodes / 12,437 edges ingested in seconds. Headline metric
panel: **5 crown jewels** across 3 domains; reachability 0 (nothing owned yet).

**0:20–0:50 — The breach.** Finding F-001 lands (infostealer dump —
*T1078.002*): `T1_TONYMONTANA@PHANTOM.CORP` marked owned. The graph lights up:
**10 shortest attack paths to Domain Admins** (7-hop chains; GMSA password-read
kill chain annotated hop-by-hop with ATT&CK technique labels).

**0:50–1:10 — The live mutation.** Finding F-003: a new `GENERIC_ALL` ACE is
granted mid-session — the edge appears **live** on the canvas; the agent
re-scores all paths immediately. (Ties to FalkorDB sub-ms writes.)

**1:10–2:20 — The interdiction cascade.** Agent proposes the top-frequency
edge. **Human gate: APPROVED.** Cut #1 executes → re-query → reachability
**1→1 (degraded)** — honest verdict: the fresh grant wasn't the real chokepoint.
Agent re-ranks → proposes `DF-MS-SHS -MEMBER_OF-> GMSA_SHS_PWD` (on 10 of 10
paths). **APPROVED** → cut #2 → reachability **1→0 COLLAPSED**, re-query ~3ms,
receipts printed: before/after, PROFILE timing, approvals, timestamps.

**2:20–2:40 — Scale wall.** Tenant switch: `sever_tenant002` is a completely
different org (disjoint SIDs) — instant graph swap, native multi-tenancy.
Then the generator: hundreds of tenant graphs in ONE FalkorDB instance,
latency-flat. (FalkorDB's signature 10K-graphs-per-instance story, made real.)

**2:40–3:00 — Provenance & close.** Receipts JSON on screen; exact Cypher from
`docs/CYPHER.md`; commit history visible (all work inside the event window);
AI-assist disclosure; one-command repro (`python scripts/rehearse.py`).

## Fallback ladder (pre-recorded segments)

1. Live deploy (FalkorDB Cloud w/ heartbeat) → 2. Self-host Docker on the build
host → 3. `scripts/rehearse.py --falkor` output recording. The mock engine never
appears in the video — only the live engine.
