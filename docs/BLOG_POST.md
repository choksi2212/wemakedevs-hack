# BloodHound finds the paths. I built the agent that cuts them.

*How I spent a hackathon teaching a graph database to do the one thing every
attack-path tool refuses to do: act — with a human gate and receipts for
every millisecond.*

Every identity-security engineer knows the workflow: run BloodHound, get a
beautiful graph of attack paths to Domain Admin, export a report, put it in a
ticket... and watch it rot. The tools that map your attack surface are
genuinely great now. The part nobody ships is the **closed loop**: prove that
a specific fix actually collapses the exposure, then show the graph changing
in front of you.

So for the WeMakeDevs × FalkorDB Graph Hacks hackathon, I built **SEVER** — an
on-call agent over an identity graph with one opinionated thesis:

> Detection is solved. Advice is solved. **Verified interdiction isn't.**

## The architecture, honestly

SEVER ingests the official BloodHound CE sample estates (Apache-2.0,
SpecterOps — 3 domains, 1,480 nodes, 12,437 edges, zero dangling references
after my ETL) into **FalkorDB**, plus the AzureHound Entra sample for the
hybrid story. On a findings stream it:

1. computes the **real exploitable paths** from compromised principals to
   crown jewels (Domain Admins, Enterprise Admins, and — in the hybrid estate
   — the Entra Global Administrator identity),
2. ranks the single edge whose removal kills the most paths (edge-frequency
   scoring over shortest paths; greedy k-cuts carry the honest (1−1/e)
   submodular bound — I cite the NP-hardness because a FalkorDB engineer
   will read this),
3. **waits for a human**. My human gate passes only on the exact value
   `True` in code, and a literal APPROVE button in the console. An LLM
   narrates findings in ATT&CK terms; it never mutates anything.

Then it re-queries and shows you the collapse. Every claim is a receipt.

## What the receipts say (live falkordb 6.0.0, real numbers)

**The interdiction loop** on the sample estate: a compromised tier-1 user
holds attack paths to five crown jewels. The agent proposes the highest-leverage
cut. First cut executes: reachability **1 → 1, verdict DEGRADED** — because the
honest verdict is that this edge wasn't the real chokepoint. The agent
re-scores, proposes the actual chokepoint, second gated cut: **1 → 0, COLLAPSED,
re-query in 2.98 milliseconds.**

I kept the "degraded" case in the demo on purpose. An agent that only ever
prints success is lying to you.

**Cross-process case memory** (the Track 2 story): investigations are LangGraph
flows checkpointed with **FalkorDBSaver** — case state lives *in the graph
database*. Process one starts an investigation and pauses at the gate. I kill
it. A **completely fresh process** resumes the same thread: the triage results
and the ranked proposal are all still there, zero re-explanation, and the
approved cut collapses reachability in 2.01ms. That's the night-shift handoff
problem, solved by the same database that holds the estate.

**The hybrid beat**: the merged AD+Entra estate has 9 bidirectional identity
bridges (password-synced users exist in both worlds — the MGM lesson).
Compromise the *cloud* identity of a synced user and you pivot across the
bridge into on-prem Domain Admin chains. Sever the cross-world bridge:
**1 → 0 in 2.76ms.**

**And the scale wall**, because FalkorDB's signature claim deserves to be
taken seriously: I generated **300 tenant graphs** (injective identity remaps,
so every tenant is a distinct org) — **444,000 nodes and 3.7 million edges in a
single instance consuming 1.29 GiB of RAM**, with canonical shortest-path
queries flat at ~3.7ms median across every sampled tenant. Sparse adjacency
matrices are not marketing.

## Things I learned shipping against FalkorDB 6.0.0

- `shortestPath` only works as a **WITH-clause expression** — the
  `MATCH p = shortestPath(...)` form that Neo4j tutorials teach is rejected.
- shortest-path hop ranges must be upper-bounded (`*..12`, no lower bound).
- `algo.SPpaths` is glorious for tie analysis but explodes combinatorially on
  cross-domain path sets (15–25s+ per pair on my estate) — keep it for
  offline analysis, use the canonical form for anything on-camera.
- The procedure returns raw integer node ids on edges, not node objects.
- The shipped container has an aggressive default query timeout that fails
  *silently*. Set `GRAPH.CONFIG SET TIMEOUT_DEFAULT 0` and pass per-query
  timeouts explicitly.

All of this is documented with the exact working Cypher in the repo — every
query the product depends on, verbatim, with PROFILE receipts.

## The point

The industry deliberately stops at advice: SpecterOps keeps its own agentic
tooling read-only, and for good reason — nobody wants an LLM mutating AD
permissions. SEVER agrees, and that's exactly why the loop closes: the graph
does the math, the human swings the axe, and the receipts prove it worked.
The database you trust to store your attack surface turns out to be exactly
the database you want running the remediation math — in milliseconds, across
hundreds of tenants.

Repo: `choksi2212/wemakedevs-hack` (public at submission — commit history
100% inside the hackathon window).

*Built solo (with AI assistance under my direction, disclosed per the rules)
at Graph Hacks, Oct 15–18 2026.*
