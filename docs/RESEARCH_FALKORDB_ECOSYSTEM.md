# RESEARCH — FalkorDB Ecosystem Scan: What Makes the Hosts Love SEVER

Branch `audit4/falkordb-ecosystem` from `origin/main` @ `7a30ede` · researched 2026-10-16.
External claims carry their URL; SEVER claims carry the repo receipt that proves them.

> **TL;DR** — FalkorDB's own marketing asks SEVER's exact question (*"What's the
> path from this leaked token to a production database?"*) and headlines Agent
> Memory + Cloud Security: SEVER is that story shipped — 300 isolated tenant graphs
> receipted at 4.67ms median, FalkorDBSaver used as real security-agent case memory,
> engine quirks mapped and published. No visible 2026 entrant is in identity
> interdiction. §5 is the judge talking points, in their own voice.

## 0. The event (prize facts per the official rules text)

> **Dated snapshot caveat (2026-10-18).** The wemakedevs.org overview and
> rules pages, re-verified today, still serve the September-era copy — a
> "$10,000" prize pool and the stale track blurbs ("Investigation and risk,
> agentic AI, or the GraphRAG SDK"). The authoritative rules text distributed
> by the organizers for this event (18 rules; prize pool **$20,000**; tracks
> **Agents That Act on Connected Data** / **Agent Memory and Coordination** /
> **Company Brain**) is what the prize facts below follow — the rules text
> over the stale site copy. Re-verify the live pages (and the
> WeMakeDevs/FalkorDB community channels) before submission.

- **Graph Hacks: Context for AI Agents**, WeMakeDevs × FalkorDB, online **Oct 15–18, 2026**, **$20,000** total — https://www.wemakedevs.org/hackathons/falkordb/schedule, https://luma.com/graph-hacks
- Tracks: **Agents That Act on Connected Data** (iPhone 18 Pro) · **Agent Memory and Coordination** (PS5 + GTA VI) · **Company Brain** (M6 Mac Mini); AirPods 5 for best blog post, tees for top-50 teams — https://luma.com/graph-hacks
- Official rules text: *"You may enter any or all of them, and you must name every track you are entering when you submit"* — multi-track entry is legal — https://www.wemakedevs.org/hackathons/falkordb/rules
- FalkorDB "needs to be the primary graph database in your project" and do real work — the graph is decoration if the product still works without it — https://luma.com/graph-hacks, https://www.wemakedevs.org/hackathons/falkordb/rules
- Submission requires a public repo, README + graph data model, **the exact Cypher the product depends on**, demo video, live deployment — https://www.wemakedevs.org/hackathons/falkordb/rules. SEVER ships every item (`docs/CYPHER.md`, `docs/receipts/`, deployed stack + Cloud receipts).

## 1. Their security-graph positioning — SEVER is their story, shipped

- FalkorDB sells security graphs as a flagship vertical: entitlement audits, IAM sprawl, lateral movement, "toxic privilege combos" — https://falkordb.com/blog/security-graphs-cloud-entitlements-guide
- Their CTO quote is the product brief: *"Graphs can turn your tangled security data into a living, interactive map, making it possible to spot risks and answer tough questions in real time"* (Roi Lipman) — same URL.
- Their own headline question — **"What's the path from this leaked token to a production database?"** — https://falkordb.com/blog/store-security-data-in-a-graph. SEVER answers exactly that for the identity estate: compromise a principal → bounded paths to crown jewels → one human-gated cut → re-query receipt in ms (`docs/INCIDENTS.md`).
- Their published security content is cloud-IAM-shaped (attack-path discovery "in minutes instead of hours" — https://falkordb.com/blog/graph-database-multi-tenant-cloud-security; "10,000+ isolated tenant graphs" — https://falkordb.com/blog/store-security-data-in-a-graph).
- The **BloodHound-shaped AD/Entra identity graph is the case their marketing hasn't shipped** — SEVER brings it: BloodHound CE + AzureHound collector JSON → two-pass BloodHound-faithful ETL → graph-per-tenant (`README.md` architecture), with hostile collector JSON treated as an attack surface (`docs/security_audit.md`).
- Payment-fraud post, same doctrine: fraud "is a property of a network", the graph is the connective tissue, "give analysts graph context not raw alerts" — https://falkordb.com/blog/payment-fraud-prevention. SEVER's evidence-over-alerts loop (receipts JSON + ms, human gate, DEGRADED/COLLAPSED verdicts) is that doctrine with an axe.
- Their README headline — *"Ultra-fast, Multi-tenant Graph Database **Powering Generative AI, Agent Memory, Cloud Security, and Fraud Detection**"* — https://github.com/FalkorDB/FalkorDB. SEVER covers **Agent Memory + Cloud Security in one product** and can say it in their words.

## 2. Flagship features — genuinely theirs, and where we go deeper

1. **Multi-graph tenancy / topology isolation** — theirs: isolated graph DBs in a single instance — https://docs.falkordb.com/cloud/features; 629 isolated graphs ≈25k QPS on one node in their own workshop, isolation "structural rather than a filter condition", fully open-source, no cross-graph single query — https://www.falkordb.com/news-updates/multigraph-topology-isolation-linear-scale/
   - Ours: **300 isolated tenant graphs in ONE instance — 444,000 nodes / 3,735,000 edges / 1.594 GiB RSS (~5.4MB per tenant), path queries flat at 4.67ms median, p95 4.81ms** (`docs/receipts/scale_wall.json`); per-tenant checkpoint graphs `sever_<tenant>_checkpoints` (`docs/T2_MEMORY.md`); we honor their documented no-cross-graph-query limit honestly instead of fighting it.
2. **GraphBLAS sparse-matrix core** — theirs: "first queryable property graph database to leverage sparse matrices … and linear algebra for querying" — https://github.com/FalkorDB/FalkorDB, https://docs.falkordb.com/design/index.md
   - Ours: the claim turned into a wall receipt — **3.74M edges in 1.59 GiB**, "sparse adjacency matrices are not marketing" (`docs/BLOG_POST.md`), measured on falkordb 6.0.0.
3. **langchain_falkordb FalkorDBSaver** — theirs: a LangGraph checkpointer persisting agent state in FalkorDB — https://github.com/FalkorDB/langchain-falkordb, https://docs.falkordb.com/genai-tools/langchain.html
   - Their shipped usage is a toy `graph.invoke({"total": 0})` counter (repo README) plus conceptual memory posts — https://falkordb.com/blog/building-ai-agents-with-memory-langchain. **No security-agent case-memory pattern exists anywhere in their docs, blog, GitHub, or any visible 2026 entry.**
   - Ours: case memory for a security agent — `taskkill /F` mid-case → a fresh process resumes the exact pre-kill interdiction proposal at 2.47ms re-query; interleaved cases A/B never cross-contaminate; a deleted checkpoints graph fails CLOSED (`docs/T2_MEMORY.md`, `docs/receipts/receipts_T2_live.json`, `docs/receipts/audit3_mem/`).
4. **algo.SPpaths** — theirs: documented source→target shortest paths with `weightProp`/`costProp`/`pathCount`/`relDirection` — https://docs.falkordb.com/algorithms/sppath.html
   - Ours (mapped live on 6.0.0, all receipted in `docs/CYPHER.md` + `docs/BLOG_POST.md`; SPpaths + shortestPath forms re-verified on Cloud 4.22.0 by `audit5_cloud_instance.json`): config takes node references, not patterns; **unknown config keys are silently ignored** (`maxHops: 2` still returns a 12-hop path) so the hop cap is enforced app-side; edges carry raw integer node ids → hops rebuilt via index-zip; explodes combinatorially on cross-domain tie sets (15–25s+); the "intermittent failure under churn" we originally logged was root-caused by audit5 to our own raw unformatted template (rejected by BOTH engines — fixed; see CYPHER.md's quirks section) → the live loop uses the canonical `shortestPath *..12` form, itself a quirk map (WITH/RETURN-expression only, not `MATCH p =`; the WITH and RETURN forms both parse on 4.22.0 and 6.0.0; no lower bounds). None of this is in their docs.
5. **GRAPH.PROFILE** — theirs: "parallel entrypoint to GRAPH.QUERY", reports records produced + ms per operation — https://docs.falkordb.com/commands/graph.profile.html
   - Ours: ms receipts as a product feature — canonical path query profiled at ~1.1ms on the 1,480n/12,450e demo tenant (`docs/receipts/profile.txt`).
   - The seam they don't document: **the Python client's `profile()` wraps an `ExecutionPlan` that drops the ms timings** (https://raw.githubusercontent.com/FalkorDB/falkordb-py/main/falkordb/graph.py), so our port reuses `_build_params_header` and keeps the RAW response (`sever/core/falkor_port.py::profile`). Their own client hides the number their own command produces.
6. **CYPHER params header** — theirs, documented for GRAPH.QUERY: `GRAPH.QUERY graph_name "CYPHER param=val … query"` for plan caching + injection safety — https://docs.falkordb.com/commands/graph.query.html (FAQ repeats the `CYPHER` prefix — https://docs.falkordb.com/cypher/index.md)
   - Ours: every product query parameterized (`docs/CYPHER.md`); the one interpolated slot (`{rel}`) is regex-validated before reaching the query string (`docs/security_audit.md`).
   - **CYPHER-header-through-GRAPH.PROFILE appears in no doc we could find** — the PROFILE page lists args as "Graph name, Query" only — so that combo is our discovery on top of their documented mechanism.

## 3. Past WMD hackathon winners — the formula

- **Cognee "Hangover Part AI"** grand winner **Lethe** (Vinayak Sonthalia): on-call incident-triage memory with *verifiable forgetting* — contrarian thesis, measured receipts ("2 documents · 10 graph nodes · 18 relationships" erasure certificate), blind-judge benchmark, full product polish, solo in one week — https://wemakedevs.org/hackathons/cognee/projects
- **SigNoz "Agents of SigNoz"**: three grand winners, each "pointed SigNoz at something real" — OTel instrumentation for CrewAI (found a genuine deployment bug), DebugProof (evidence-scored release gate), RootCause (hydroponic farm, live deployment); the pre-event blog won on an honest, reproducible self-hosting write-up — https://archive.wemakedevs.org/hackathons/signoz/projects
- **Motia "Backend Reloaded"**: Orchestrix (visual backend builder, 1st), SocialOps, OpsGuard — production tools, not demos — https://archive.wemakedevs.org/hackathons/motiahack25/projects
- **Coral "Pirates of the Coral-bean"**: 270+ PRs into the sponsor's own OSS, plus a top-blogs track — https://archive.wemakedevs.org/hackathons/coral/projects
- **The formula**: (1) a real infra problem the sponsor's team recognizes; (2) production-grade polish — deployed, demo video, repo receipts; (3) measured, adversarially verified evidence; (4) sponsor-OSS goodwill; (5) a blog — Graph Hacks literally pays AirPods 5 for the best one (https://luma.com/graph-hacks; SEVER already has `docs/BLOG_POST.md`). SEVER matches the Lethe/DebugProof DNA: self-attacked claims (`docs/receipts/audit3_mem/`), honest DEGRADED-vs-COLLAPSED verdicts (`docs/INCIDENTS.md`).

## 4. 2026 entrant scan (visible Oct 16, mid-hackathon)

- **Trace** — research agent whose memory is a FalkorDB graph — https://dev.to/swarnnim/why-i-put-my-agents-memory-in-a-graph-1l6b (memory-track flavored)
- **PatchPath** — Python repo parsed into a FalkorDB knowledge graph, benchmarked on 12 frozen real bugs — https://dev.to/sansk_ya/i-froze-12-real-bugs-and-measured-my-hackathon-project-against-them-all-day-5ekb (company-brain flavored)
- GraphRAG SDK demo benchmarked against Neo4j — https://dev.to/danshalev7/i-built-a-graphrag-demo-with-falkordbs-new-sdk-then-benchmarked-it-against-neo4j-3hh; FalkorDB vector-search gotcha — https://dev.to/eyanpen/a-falkordb-vector-search-gotcha-why-wont-dbidxvectorquerynodes-work-1bio; event round-up — https://daily.dev/posts/dev-opportunity-radar-19-hacktoberfest-20k-ai-agent-hackathon-and-pear-prime-2027-grstii7l7
- Coverage gaps: X `#BuildWithFalkorDB` surfaced nothing via public web search (X requires login); the FalkorDB Discord showcase channel is not publicly indexed (invite open for the whole event — https://discord.com/invite/Y2mMT9VdMy, per the schedule page).
- **No visible entrant is in identity security / attack-path interdiction.** Public themes: research-agent memory, code graphs, GraphRAG benchmarks. SEVER's niche — BloodHound-shaped estates, human-gated interdiction, MSSP multi-tenancy — is uncontested in everything publicly visible.

## 5. Judge talking points (in FalkorDB's own voice)

1. "SEVER is your security-graph story, shipped: your own post asks *"What's the path from this leaked token to a production database?"* — we answer it live for AD/Entra identity estates, with BloodHound-shaped data native in FalkorDB and single-cut collapse receipts in milliseconds."
2. "Your multigraph claims, receipted at scale: **300 isolated tenant graphs in one open-source instance — 444,000 nodes, 3.74M edges, 1.59 GiB RSS, path queries flat at a 4.67ms median**. We ran your linear-scale-and-isolation workshop on our own hardware and kept the JSON."
3. "The first real-world FalkorDBSaver ship we can find anywhere: not the README's toy counter — **case memory for a security agent**, one checkpoint graph per tenant; a killed process resumes the exact pre-kill interdiction proposal at 2.47ms, adversarially audited."
4. "We treat your engine the way your team does: GRAPH.PROFILE ms receipts straight from the raw response (your Python client's ExecutionPlan wrapper drops the timings), the CYPHER params header driven through PROFILE, and algo.SPpaths' undocumented quirks — silently-ignored config keys, raw node ids — mapped live and published verbatim per the rules."
5. "Your README headlines 'Agent Memory, Cloud Security' — SEVER productionizes both in one product, and with no visible 2026 entrant in identity security, this entry also hands your sales team the security-graph case study your blog hasn't shipped yet."
