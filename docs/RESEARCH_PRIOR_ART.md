# SEVER — Academic Prior-Art Search (branch audit4/prior-art)

Date 2026-10-16. Question: **has SEVER already been built or published?** Sources: arXiv,
ACM DL, Springer, ScienceDirect, dblp, vendor archives.

> **TL;DR** — **No published work builds SEVER's loop.** Every *component* has
> precedent (greedy max-coverage ranking, Stackelberg AD-graph interdiction,
> human-approval gates, graph-DB substrates) — the closed loop on a live multi-tenant
> graph DB with per-cut receipts is unclaimed. Novelty is **systems integration**, not
> the heuristic. The citable paragraph is **Precise novelty statement** below; the
> cheap addable ideas are at the end.

## Verdict

**No published work builds SEVER's loop.** Every *component* has precedent — greedy
max-coverage edge ranking, Stackelberg AD-graph interdiction, human-approval gates,
graph-DB security substrates, detectability-aware scoring — but no paper or system closes
SEVER's operational loop: findings → attack-path walk → **human gate** → sever on the
**live multi-tenant graph DB** → immediate re-query verification → before/after receipts,
per-tenant, in milliseconds. SEVER's novelty is **systems integration**, not the heuristic.

## 1. Attack-graph interdiction / critical-node & critical-edge detection (CNP/CEP)

- **Sheyner, Haines, Jha, Lippmann, Wing, "Automated Generation and Analysis of Attack
  Graphs," IEEE S&P 2002.** Minimum Critical Set of Attacks is NP-complete via reduction
  from **minimum cover**; greedy minimal-critical-set algorithm; MDP reliability analysis.
  This *is* SEVER's algorithmic family — the README's "set-cover-family greedy" is exact.
- **Arulselvan, Commander, Elefteriadou, Pardalos, "Detecting critical nodes in sparse
  graphs," Computers & OR 36(10):2193–2200, 2009.** Canonical CNP ILP + heuristic.
- **Walteros & Pardalos, "Exact interdiction models and algorithms for disconnecting
  networks via node deletions," Discrete Optimization 9(3), 2012.** (The brief's "Walter
  et al." resolves here; no other "Walter" CNP paper found.)
- **Veremyev, Boginski, Pardalos, "An integer programming framework for critical elements
  detection in graphs," J. Comb. Optim. (2015), doi:10.1007/s10878-014-9730-4** — nodes and edges.
- **Lalou et al., "The critical node detection problem in networks: a survey," Computer
  Science Review 28:68–92, 2018.** Heuristic-vs-exact taxonomy.
- **Hosteins et al., "Critical node/edge detection problems on trees," 4OR (2022),
  doi:10.1007/s10288-022-00518-0** — CEDP and joint node+edge removal variants.
- **Nandi, Medal, Vadlamani, "Interdicting attack graphs to protect organizations from
  cyber attacks: a bi-level defender–attacker model," Computers & OR 75:118–131, 2016,
  doi:10.1016/j.cor.2016.05.005.** Closest general attack-graph interdiction paper
  (Stackelberg, constraint/column generation).
- **Bayarsaikhan, Chinchuluun, Arulselvan, Pardalos, "Heuristic algorithms for the
  stochastic critical node detection problem," arXiv:2512.01497 (2025)** — greedy + CELF.
- Note: a "Blaeser et al." CNP/CEP paper could **not** be located (empty arXiv/dblp hits);
  the set above is the canonical formulation record.
- **Human-in-the-loop + live re-verification: none of this line has it.** All optimize
  static snapshots offline; no gate, no post-cut re-query.

## 2. Identity-graph (Active Directory) hardening

Dense, active line — all offline planning on snapshots:

- **Guo, Li, Neumann, Neumann, Nguyen, "Practical Fixed-Parameter Algorithms for
  Defending Active Directory Style Attack Graphs," arXiv:2112.13175 (2021)** — shortest-path
  edge interdiction, treewidth/splitting-node FPT, GNN heuristic.
- **Guo, Ward, Neumann, Neumann, Nguyen, "Scalable Edge Blocking Algorithms for Defending
  Active Directory Style Attack Graphs," arXiv:2212.04326 (2022)** — edge *failure rates*,
  tree-decomposition DP, kernelization, RL.
- **GECCO 2022 (arXiv:2204.03397) + ACM journal version (2025), doi:10.1145/3688401** —
  edges carry **detection rates and failure rates**; #P-hard; EDO defender policies.
- **AAMAS 2023, "A Scalable Double Oracle Algorithm for Hardening Large Active Directory
  Systems," doi:10.1145/3579856.3590343** — millions of entities; explicitly shows
  **GoodHound's busiest-edge ("weakest link") frequency ranking is NOT success-optimal**.
  Key published caveat for SEVER's greedy.
- **Zhang, Ward, Nguyen, "Rethinking Attack Path Management: A New Metric for Choke Points
  in Attack Graphs," IEEE CSF 2025** — connection-intersection choke-point metric;
  **human experiments** with white-hat hackers showing shortest-path-mapping volatility.
- **Ngo, "Practical Graph Optimisation and AI-Driven Models for Active Directory Security
  Hardening," PhD thesis, arXiv:2607.22009 (Jul 2026)** — *closest academic thing to
  SEVER's human gate*: adaptive prioritisation that **queries the IT admin for mediation
  per high-risk path**, plus an edge-removal policy generalizing admin decisions, plus
  dynamic-graph decoy placement. Still a decision model — no deployed act-on-DB loop,
  no receipts, single estate.
- **Dunagan et al. 2009 ("Triage")** — Microsoft attack-graph-subset recommendation;
  BloodHound's intellectual ancestor (per the AD literature).
- **"Start thinking in graphs…," Int. J. Inf. Secur. (2023), doi:10.1007/s10207-023-00751-6**
  — Neo4j+BloodHound graph-analytics platform for a Microsoft cloud tenant; measurably
  reduces attack paths. Offline assessment, single tenant.
- Password-specific graph hardening: nothing surfaced — this line is all privilege-edge
  removal (monitor or revoke).

## 3. Graph-DB-based security agents (substrate)

- **Vallabhaneni, Cagwin, Wild, "SENTINEL-RL: Offloading Topological Reasoning from LLM
  Agents in the Security Operations Center," arXiv:2609.04159 (Sep 2026)** — *closest
  published systems cousin*: live **Neo4j** auth-event graph (24M edges), HetGAT+PPO
  recommendations, LangChain narratives, and "cannot execute any infrastructure changes
  without a human operator clicking a final approval gate"; full
  detect→investigate→recommend→**human-approve** cycle in 6.3 s median. But it is
  detection/containment on *authentication telemetry*, not identity attack-path
  interdiction; single tenant; no before/after reachability receipts.
- **"An Organization-Scoped LLM Agent Runtime Architecture for Regulated Cybersecurity
  Operations," arXiv:2605.30604 (2026)** — tiered HITL gates + append-only audit;
  architecture paper; no graph interdiction.
- **Hound, arXiv:2510.09633 (2025)** — relation-first knowledge graph for *code* audits.
- Vendor/practitioner: FalkorDB markets multi-tenant "security graphs" for CNAPP/CSPM/CIEM
  (falkordb.com/cyber-security) — *detection/surfacing only*, no act-on-graph interdiction
  loop. BloodHound CE (Neo4j) is advisory-only, single estate. **BloodHound Enterprise**
  (closed-source) recommends choke-point remediation with re-scans; public record shows no
  inline human gate on the live DB with per-cut receipts.
- **No published academic system uses a graph database as the live interdiction substrate
  with tenants.**

## 4. Deception / detectability-aware ranking ("NoiseHound lineage")

- Academic line: GECCO'22/ACM'25 detection-rate-weighted Stackelberg games →
  **Ngo, Guo, Nguyen, "Catch Me if You Can: Effective Honeypot Placement in Dynamic AD
  Attack Graphs," arXiv:2312.16820 (2023)** → **Ngo, Guo, Nguyen, "Optimizing Cyber
  Response Time on Temporal Active Directory Networks Using Decoys," arXiv:2403.18162
  (2024)**.
- **NoiseHound** (warpedatom, GitHub; velkris.red, Aug 2026) is a **practitioner tool, not
  a paper**: re-ranks BloodHound paths by lab-measured per-technique telemetry across
  audit/EDR/SIEM tiers; path score 0.6·max+0.4·mean; noisy-OR detection probability;
  Pareto frontier over (noise, hops, probability). **Attacker-side** (quietest route).
- Line status: game-theoretic detectability weights (2022–24) → measured-telemetry attacker
  tooling (2026). **Nobody published defender-side detectability-weighted cut ranking.**

## Precise novelty statement for SEVER

1. The greedy edge-frequency (max-coverage) ranking is the modern instantiation of Sheyner
   et al.'s (2002) greedy minimum-critical-set family and equals GoodHound's busiest-path
   heuristic — AAMAS'23 shows it is not success-optimal (cited honestly in our docs).
2. Exact/Stackelberg interdiction on AD graphs is a mature *offline research* line
   (Nandi 2016; Guo 2021–22; AAMAS'23) — none of it executes on a live system.
3. **Unpublished anywhere**: the closed loop itself — live findings stream → attack-path
   walk on a **live multi-tenant graph database** (FalkorDB native multi-graph,
   `sever_demo`/`sever_tenantNNN`) → human-gated edge sever **through the same DB** →
   immediate re-query reachability verification (2.28 ms) → **before/after receipts with
   honest DEGRADED/COLLAPSED verdicts** → cross-process case memory persisted in the same
   DB. Sentinel-RL has the gate but on auth-event graphs, single-tenant, no receipts;
   Ngo's thesis has admin feedback only as an optimization model; BloodHound Enterprise
   advises but does not prove cuts on the live DB with per-tenant receipts.
   **Per-tenant interdiction-as-a-service on a graph DB is unclaimed in the literature.**

## Published ideas cheaply addable in-window (feeds backlog)

1. **CSF'25 choke-point metric in receipts** (Zhang, Ward, Nguyen 2025): alongside binary
   reachability, count *exposed principals* (nodes with any path to the crown jewel)
   before/after each cut and record the delta — one Cypher COUNT per side (~20 lines);
   upgrades receipts from reachability to a peer-reviewed exposure metric.
2. **NoiseHound-style loudness table** (warpedatom 2026): static per-relationship-type
   detection-cost dict; post-cut receipt flags whether the *quietest* surviving route got
   quieter — attacker-preference-aware cut ranking (~40 lines, no new deps).
3. **Doc-only**: cite AAMAS'23's busiest-edge ≠ success-optimal result beside the greedy
   ranking — strengthens the honest-DEGRADED positioning (zero code).
4. Optional: CELF lazy-greedy (arXiv:2512.01497) if the ranking loop ever becomes
   hot-path — unnecessary at 12k-edge scale.

## References (short)

1. Sheyner et al., IEEE S&P 2002 · 2. Arulselvan et al., C&OR 2009 · 3. Walteros & Pardalos,
   Discr. Optim. 2012 · 4. Veremyev et al., JCO 2015 (doi:10.1007/s10878-014-9730-4) ·
   5. Lalou et al., CSR 2018 · 6. Nandi et al., C&OR 2016 (doi:10.1016/j.cor.2016.05.005) ·
   7. arXiv:2112.13175 · 8. arXiv:2212.04326 · 9. arXiv:2204.03397 + doi:10.1145/3688401 ·
   10. AAMAS'23 doi:10.1145/3579856.3590343 · 11. Zhang, Ward, Nguyen, CSF 2025 ·
   12. arXiv:2312.16820 · 13. arXiv:2403.18162 · 14. arXiv:2607.22009 · 15. arXiv:2609.04159 ·
   16. arXiv:2605.30604 · 17. arXiv:2510.09633 · 18. IJIS 2023 doi:10.1007/s10207-023-00751-6 ·
   19. arXiv:2512.01497 · 20. 4OR 2022 doi:10.1007/s10288-022-00518-0 ·
   21. NoiseHound: github.com/warpedatom/noisehound + velkris.red (2026) ·
   22. falkordb.com/cyber-security (vendor positioning)
