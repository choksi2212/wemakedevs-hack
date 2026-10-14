# SEVER

**Attack-path tools stop at advice. SEVER closes the loop: ranked cut → human gate →
live re-query → before/after receipts — per-tenant, in milliseconds.**

An on-call identity-security agent on [FalkorDB](https://falkordb.com): it ingests
BloodHound-style Active Directory identity graphs, reacts to a live findings
stream, walks the real exploitable paths to Domain Admin, ranks the one edge
whose removal kills the most paths, and — only after an explicit human
approval — severs it and proves the attack surface actually collapsed.

Built at **Graph Hacks** (WeMakeDevs × FalkorDB), Oct 15–18 2026.

> **Branch map:** development happens on `feat/*` branches merged into `develop`
> (always green). `main` holds a stub README until final submission. Track
> `develop` for the real thing.

---

## The demo beat (measured, not promised)

On the official BloodHound CE sample estate (3 domains, 1,480 nodes, 12,437 edges):

```
[F-001] credential_breach   → T1_TONYMONTANA marked owned
        10 shortest attack paths to Domain Admins (7-hop GMSA kill chain)
[F-003] ace_granted         → new GenericAll edge granted LIVE mid-session
        agent re-scores all paths instantly
-- interdiction round 1 (human-gated): cut the fresh ACE grant
        reachability 1 -> 1   verdict: DEGRADED (honest — not the real chokepoint)
-- interdiction round 2 (human-gated): cut DF-MS-SHS -MEMBER_OF-> GMSA_SHS_PWD
        reachability 1 -> 0   verdict: COLLAPSED, re-query 2.95ms
```

Reproduce it yourself (offline mock engine, no FalkorDB needed):

```bash
pip install -e ".[dev]" && python scripts/rehearse.py
```

Or against the real engine: `docker compose up -d` then
`python scripts/rehearse.py --falkor` (receipts land in `out/receipts_*.json`).

## How it works

```
BloodHound CE collectors ──▶ ETL (two-pass, BloodHound-faithful)
        │                        │  1,480 nodes / 12,437 edges / 0 dangling
        ▼                        ▼
 findings stream ──▶ SEVER agent ──▶ FalkorDB (graph-per-tenant)
 (breach-timeline        │  paths, scoring, proposals        │
  replay, live-mutating) ▼                                   ▼
                   HUMAN GATE ──▶ cut ──▶ re-query ──▶ receipts (PROFILE, ms)
```

- **FalkorDB is load-bearing** (rule 3): every path query, score, cut and
  re-verification is FalkorDB Cypher — `sever/core/falkor_port.py` holds the
  exact queries as module constants, reproduced in [`docs/CYPHER.md`](docs/CYPHER.md).
- **Graph data model**: [`docs/GRAPH_MODEL.md`](docs/GRAPH_MODEL.md).
- **Human gate**: `approve_and_cut()` passes *only* on the exact value `True` —
  no caller can slip a truthy value through. The LLM narrates; Cypher works;
  a human decides. (SpecterOps keeps its own agentic tooling read-only for the
  same reason.)
- **LLM seam**: any OpenAI-compatible endpoint via env config, with an offline
  `NullLLM` fallback — the product never depends on a model to function.
- **Multi-tenancy**: one graph per tenant org — `sever_demo`,
  `sever_tenant001..N` — FalkorDB's native multi-tenancy; identity remapping is
  injective by construction (`sever/synth/tenants.py`).

## Quickstart

```bash
git clone https://github.com/choksi2212/wemakedevs-hack && cd wemakedevs-hack
docker compose up -d                      # FalkorDB 6.0.0 + browser UI at :3000
mkdir -p data/ad_sample && cd data && curl -sLO \
  https://raw.githubusercontent.com/SpecterOps/BloodHound-Docs/main/docs/assets/sample-data/ad_sampledata.zip \
  && unzip ad_sampledata.zip -d ad_sample && cd ..
pip install -e ".[dev]"
python -m pytest                          # 41 tests, green
python scripts/rehearse.py --falkor        # the demo beat, with receipts
```

## Tests

41 tests across ETL (data fidelity vs the real sample), both graph ports,
interdiction scoring, the human gate, findings stream and tenant generation —
including the measured hero-beat regression (10 paths → cut → 0).

## Disclosures

- **Simulated environment**: the estate is built from the official SpecterOps
  BloodHound CE sample data (Apache-2.0, credited in-repo); findings are a
  labeled deterministic breach-timeline replay. No real organization's data.
- **AI-assisted development** (rule 11): this project was built with AI
  assistance under human direction — architecture decisions, graph model,
  traversal semantics, acceptance criteria and every merge were reviewed by the
  author, who can defend each component. Commit history is fully in-window.
- **Track**: Agents That Act on Connected Data (primary).

## Project layout

```
sever/etl/         collector parsing → normalized graph → Cypher batches
sever/core/        GraphPort (mock + FalkorDB), traversal semantics, scoring
sever/findings/    deterministic stream + ATT&CK narration map
sever/agent/       LLM seam + investigator loop with hard human gate
sever/synth/       injective multi-tenant identity generator
scripts/rehearse.py  end-to-end demo + receipts
docs/              graph model, exact Cypher, demo script
```
