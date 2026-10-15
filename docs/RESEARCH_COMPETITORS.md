# SEVER competitor landscape — receipts

> Audit 4. Answers the judge's kill question — *"isn't this just BloodHound rehosted?"* — with one URL per claim.
> Every tool below was checked for the five things SEVER does in one loop: **rank the cut → human-gate it →
> execute it → re-query the graph → emit a before/after receipt**, plus graph-per-tenant on FalkorDB and
> cross-process case memory. Compiled 2026-10-16 on branch `audit4/competitor-landscape`.

## Verdict

**No product on the market closes the interdiction loop.** Every player stops at discovery, ranking,
and remediation *advice*. BloodHound Enterprise (BHE) is the closest — it ranks choke points and tracks
exposure over time — but its own copy says it "delivers tailored **remediation guidance** to shut those
pathways down" (https://specterops.io/platform/bloodhound-enterprise/), and the AWS listing is explicit:
"Enables rapid remediation **with guidance and progress tracking**" (https://aws.amazon.com/marketplace/pp/prodview-nne5kiarmhfwi). The human executes the change in AD/Entra; no tool executes the cut, re-queries
the graph, and hands you a measured receipt. BloodHound format is SEVER's **input**, not SEVER's product.

## 1. SpecterOps / BloodHound family

- **BloodHound CE** (OSS): discovery/visualization only — "uncovers and analyzes attack paths in minutes"
  (https://specterops.io/bloodhound-community-edition). Unweighted shortest paths, no cut ranking, no
  execution, no verification, single local graph. NoiseHound's README agrees: "BloodHound / BloodHound CE
  find *a* path by unweighted hop count. No noise model." (https://github.com/warpedatom/NoiseHound)
- **BloodHound Enterprise**: SaaS APM. "Risk-based Choke Point Analysis … Pinpointing Choke Points to
  block the largest number of pathways … Ranking remediation Choke Points by collective risk reduction"
  (https://specterops.io/scaling-beyond-bloodhound-ce) — same core idea as SEVER's ranked single-edge cut.
  Marketing: "17K+ paths cut per choke point", "2B+ abusable relationships" (AWS listing, above) — but
  "cut" there means a human fix, advised. **Does it cut? No.** **Does it re-verify?** Yes, via continuous
  collection: "Resolved Attack Paths are immediately reflected in BloodHound Enterprise, allowing teams to
  confirm successful remediation based on defensible risk metrics" (https://specterops.io/blog/2022/03/03/attack-path-management-pillars-part-3-safe-ad-security-remediation-guidance) — posture trending, not
  per-cut receipts. **Per-tenant?** Multi-client SaaS on their infrastructure; no graph-per-tenant engine
  you control or query. Independent description: "ranks remediations by impact: which single configuration
  change will eliminate the most paths" (https://risky.biz/catalog/specterops-bloodhound-enterprise).
- **BloodHound Hunter** (Jul 2026, MCP agent interface): verifiably **read-only** — "Hunter is read-only,
  respects existing user permissions, and keeps your data authoritative in BloodHound Enterprise while you
  bring your own approved agents" (https://specterops.io/news/specterops-extends-attack-path-management-across-hybrid-and-agentic-ai-workflows/).
  OpenAI Daybreak partnership stays advice-side too: agents "surface prioritized remediation guidance"
  (https://specterops.io/blog/2026/06/22/specterops-openai-daybreak-ai-cyber-innovation/).
- **BloodHound Scentry** = managed APM service, not tooling (https://lelezard.com/en/news-22109253.html).
- Name-checks that did **not** verify: **"SpecterOps Ranger"** — no public product by that name exists
  (multiple searches, 0 hits); their agentic line is Hunter, read-only per above. **"zipslip remediation
  guidance"** — no such BHE feature; ZipSlip is Snyk's archive path-traversal vuln
  (https://snyk.io/blog/zip-slip-vulnerability). BHE's real guidance receipt is the Practical/Precise/Safe
  pillars post linked above. Don't cite either name to judges.

## 2. Open-source re-rankers — all ANALYZE, none execute or re-verify

- **GoodHound**: busiest paths + "weakest links" + exploit-cost risk score "to prioritise remediation of
  attack paths"; outputs CSV/markdown, local DB for review-to-review diffing (https://github.com/idnahacks/GoodHound).
- **NoiseHound**: re-ranks paths by lab-measured **detection cost** (77-edge telemetry corpus, 5 tiers);
  `--defensive` mode ranks detection gaps; Pareto/noise/probability modes (https://github.com/warpedatom/NoiseHound).
- **PlumHound**: BloodHound report engine + busiest-path module (https://github.com/PlumHound/PlumHound).
  **ImproHound**: tier-violation analysis (positioning per NoiseHound README, above).
- **ADPathFinder** (NetSPI, 2026): attack-path mapping across AD/ADCS/MSSQL/SCCM via OpenGraph collectors,
  groups shared paths, pairs NTDS+hashcat potfiles; HTML report has "remediated state tracking" —
  manually marked (https://github.com/NetSPI/AD-PathFinder, https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce).
- **AutoHound**: Claude reasons over BloodHound graph, ATT&CK-mapped exploitation commands (https://github.com/geo2x/AutoHound).
- **"Plasma" / "BTA (BackTrack Attacks)"**: could not be verified as public AD attack-path tools after
  multiple searches (only Plasma desktop / defunct BackTrack Linux). Treat as noise.

## 3. Commercial identity attack-path players — none close a receipt loop

- **Veza**: Authorization/Access Graph, blast radius, access reviews; "Actions" can change access, but
  re-verification is re-extraction, not per-cut measured receipts (https://veza.com/blog/inside-vezas-ai-agent-security-for-google-cloud-vertex-ai-a-technical-deep-dive).
- **Silverfort**: ISPM surfaces shadow admins etc. with "guided remediation"; Runtime Access Protection
  **blocks at authentication** (MFA/JIT/virtual fencing) — runtime enforcement, never cuts graph edges
  (https://silverfort.com/blog/5-ways-to-step-up-your-ad-hygiene-with-silverfort, https://silverfort.com/platform/).
- **Okta Identity Threat Protection** (absorbed Authomize): continuous session/entity risk → automated
  session revocation / Universal Logout / quarantine — response actions, not graph surgery, no receipts
  (https://www.okta.com/products/identity-threat-protection/, https://help.okta.com/oie/en-us/content/topics/itp/overview.htm).
- **Axonius**: CAASM + Identities; attack-path analysis is network-reachability + finding-priority
  context; AI "recommended actions" + rule engine + ownership SLAs — remediation routing, no loop receipts
  (https://axonius.com/blog/attack-path-analysis-beyond-cloud, https://helpnetsecurity.com/2026/04/15/axonius-expands-asset-cloud).
- **Omada Identity Cloud**: IGA — ML role mining, certifications, lifecycle; no attack-path model at all
  (https://omadaidentity.com/functionality).
- **SPHERE (SPHEREboard)**: closest hygiene **remediation loop** — "automatic remediation", ownership,
  audited workflows, drift monitoring — but identity hygiene, no attack-path enumeration, no path-collapse
  measurement (https://prnewswire.com/news-releases/sphereboard-6-2-release-to-streamline-identity-hygiene-with-precise-visibility-and-contextual-remediation-301598874.html,
  https://yespress.io/sphere).

## 4. Academic attack-graph interdiction — formulations, not systems

Budgeted arc removal is well-studied: bi-level defender–attacker interdiction with limited budget
(https://sciencedirect.com/science/article/pii/S0305054816301113); minimum-cost hardening via initial
conditions (NP-hard min critical set; polynomial minimal set) (https://sciencedirect.com/science/article/pii/S0140366406002271);
dominating-set-as-set-cover hardening (https://link.springer.com/article/10.1007/978-3-319-22915-7_32);
Force Path Cut = Weighted Set Cover (https://arxiv.org/html/2104.03761v1); minimal cut sets optimal only
in the limit (https://link.springer.com/chapter/10.1007/978-3-030-04834-1_5). Hale et al. build
generators/analysis, not interdiction products (https://dl.acm.org/doi/fullHtml/10.1145/3491257).
**No published system executes + re-measures on live identity graphs.** SEVER's honest framing: the math
is prior art; the shipped loop is not.

## 5. FalkorDB / Redis-graph security tools

FalkorDB sells the **substrate** to CNAPP/CSPM/CIEM vendors and demos webinar-grade analyses (Monte-Carlo
ransomware blast radius, betweenness-centrality chokepoints, multi-tenant 10K-graph isolation)
(https://falkordb.com/blog/store-security-data-in-a-graph, https://falkordb.com/blog/graph-algorithms-cybersecurity-webinar,
https://atlas.verdantix.com/falkordb/falkordb-security-graph). **No shipping identity-interdiction
product on FalkorDB** — SEVER is the end-user loop on that engine.

## Gap matrix (who does what)

| Tool | Ranks best cut | Executes cut | Re-verifies | Per-cut receipts | Tenant graphs | Case memory |
|---|---|---|---|---|---|---|
| BHE | yes (choke pts) | no — human does | yes (re-collect) | no | SaaS multi-client | no |
| BH CE / re-rankers | partial | no | no | reports only | no | no |
| Veza / Axonius / Omada | findings/priorities | partial (access/rules) | re-extract | no | no | no |
| Silverfort / Okta ITP | exposures | runtime block only | continuous | alerts | no | no |
| SPHERE | hygiene ranks | yes (audited wf) | drift monitor | audit evidence | no | no |
| Academic | formulates | no | n/a | n/a | n/a | n/a |
| **SEVER** | **yes, per edge** | **yes, gated** | **yes, re-query** | **yes, ms-precise** | **yes, FalkorDB** | **yes, in-graph** |

## Features THEY have that SEVER LACKS (backlog)

1. Continuous scheduled collection; collectors for AD, Entra, AWS, Okta, GitHub, Jamf, Entra Agent ID (BHE, https://specterops.io/news/specterops-extends-attack-path-management-across-hybrid-and-agentic-ai-workflows/).
2. Longitudinal posture dashboard — exposure % tracked over time (BHE pillars post, §1).
3. Bi-directional "Butterfly" impact analysis (BHE v6.3, https://specterops.io/blog/2024/12/12/unwrapping-bloodhound-v6-3-with-impact-analysis).
4. Privilege Zones policy enforcement (BHE, AWS listing).
5. MCP server for BYO AI agents on the graph (BloodHound Hunter, §1).
6. Runtime enforcement at the authentication layer (Silverfort RAP; Okta Universal Logout, §3).
7. Lab-measured per-edge detection-noise corpus + detection-gap ranking (NoiseHound, §2).
8. Exploit-cost risk scoring, weakest-links report, management charts, review diffing (GoodHound, §2).
9. ADCS/MSSQL/SCCM cross-dataset graphs; NTDS/hashcat password-audit pairing (ADPathFinder, §2).
10. LLM attacker-tradecraft path narration with ATT&CK-mapped commands (AutoHound, §2).
11. Ownership assignment, audited remediation workflows, drift monitoring (SPHERE, §3).
12. Certification campaigns, role mining, access requests (Omada/Veza/Axonius, §3).
13. Formal budgeted-interdiction guarantees (academic, §4).
14. Asset/identity inventory breadth — 1,400+ adapters (Axonius, https://helpnetsecurity.com/2026/04/15/axonius-expands-asset-cloud).
