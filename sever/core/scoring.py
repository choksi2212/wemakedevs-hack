"""Interdiction scoring — edge ranking, greedy k-cut PLANS, receipts.

Math honesty (README material):
- Frequency is coverage of the ENUMERATED paths: exactly one canonical
  shortest path per (owned, jewel) pair (ties off by default), so
  "paths_on" counts pair-coverage, not all possible routes.
- k=1: the max-frequency edge is the exact argmax of enumerated-path
  coverage (trivially — frequency IS that count). It still may not collapse
  reachability: alternative or tied routes survive the cut, and the
  receipt reports that honestly ("DEGRADED", never a silent success).
- k>1 (plan_cut_sequence): each round re-enumerates paths on the MUTATED
  graph — a GRAPH.COPY scratch of the live estate — and again picks the
  exact single-edge coverage argmax. This is greedy-RANKED, not an
  approximation algorithm with a provable bound: because the path set is
  re-enumerated after every cut, the k-cut sequence optimizes
  pairs-disconnected — a supermodular objective (increasing returns when
  parallel routes die together), for which greedy carries NO classic
  guarantee. The famous (1 - 1/e) submodular bound applies only to greedy
  over a FROZEN path set, which this product deliberately does not compute:
  every receipt must re-measure the live engine, not a cached enumeration.
  We therefore say "greedy-ranked", never "optimal", never "bound".
  Optimal multi-edge interdiction is NP-hard (Israeli & Wood 2002;
  AAAI'22 arXiv:2112.13175 formalizes the AD variant).
- Every plan projection is MEASURED on the mutated scratch copy — never
  simulated from a frozen enumeration. Projections can still go stale the
  moment reality diverges (the live estate mutated after planning), which
  is why Investigator.execute_plan re-measures each step and STOPS at the
  first drift instead of trusting the plan.
- "Kills most paths (N of M)" — never "all paths" unless re-measured to zero.
- Collateral (benign usage): an edge can sit on the attacker's paths AND on
  other, non-owned principals' canonical jewel paths — cutting it disrupts
  their (possibly legitimate) access too. Ranking breaks coverage ties in
  favor of LOW benign usage: among equally-covering cuts, prefer the edge
  that carries no one else's flows. The number is a sampled estimate
  (BENIGN_SAMPLE_SIZE non-owned principals, deterministic stride), labeled
  with its sample size on every receipt.
"""
from __future__ import annotations

import time
from typing import Any

from sever.core.jewels import DEFAULT_HOP_CAP
from sever.core.port import GraphPort

# How many non-owned principals are sampled for the benign-usage (collateral)
# estimate. Sampling is deterministic (sorted objectids, even stride), so the
# same estate always receipts the same numbers — replay-identical like every
# other SEVER artifact.
BENIGN_SAMPLE_SIZE = 25


def rank_cut_candidates(
    freq: dict[tuple[str, str, str], int],
    limit: int = 10,
    benign: dict[tuple[str, str, str], int] | None = None,
) -> list[dict[str, Any]]:
    """Edge-frequency ranking — the agent's remediation proposal list.

    Total order, replay-identical: attack-path coverage desc, then benign
    usage asc when ``benign`` is supplied (the collateral tie-break: an edge
    that also carries other principals' flows loses the tie to an
    attacker-only edge), then lexicographic (src, rel, dst).
    """
    def _key(kv: tuple[tuple[str, str, str], int]) -> tuple[int, int, tuple[str, str, str]]:
        (s, r, d), c = kv
        return (-c, benign.get((s, r, d), 0) if benign is not None else 0, (s, r, d))

    ranked = sorted(freq.items(), key=_key)[:limit]
    out: list[dict[str, Any]] = []
    for (s, r, d), c in ranked:
        item = {"src": s, "rel": r, "dst": d, "paths_on": c}
        # None = not measured (the fast-path triage proposal); 0 = measured,
        # no sampled benign flow crosses this edge (attacker-only).
        item["benign_usage"] = benign.get((s, r, d), 0) if benign is not None else None
        out.append(item)
    return out


def benign_edge_usage(
    port: GraphPort,
    hop_cap: int = DEFAULT_HOP_CAP,
    sample_size: int = BENIGN_SAMPLE_SIZE,
) -> dict[str, Any]:
    """Collateral estimate: non-owned principals' canonical jewel paths.

    For each sampled NON-owned principal, enumerate its canonical shortest
    paths to the crown jewels and count — per edge — how many DISTINCT
    principals use it. An edge with benign_usage > 0 carries someone else's
    access story: cutting it may disrupt that principal, not just the
    attacker. ``benign_usage == 0`` edges are attacker-only cuts.

    Requires the port to list principals (``user_objectids``); sampling is a
    deterministic even stride over the sorted non-owned pool, so receipts are
    replay-identical. Returns ``{"usage": edge->count, "sampled": n,
    "pool": m}`` — receipts must cite ``sampled``/``pool`` next to any number
    from ``usage`` (a sampled estimate is labeled as one, never passed off
    as an exact count).
    """
    lister = getattr(port, "user_objectids", None)
    if lister is None:
        raise TypeError(
            "benign_edge_usage requires a port that can list principals "
            "(user_objectids) — supply benign=None for a coverage-only ranking"
        )
    owned = set(port.owned_ids())
    pool = sorted(set(lister()) - owned)
    step = max(1, len(pool) // sample_size) if pool else 1
    sample = pool[::step][:sample_size] if pool else []
    usage: dict[tuple[str, str, str], int] = {}
    for principal in sample:
        hops: set[tuple[str, str, str]] = set()
        for path in port.paths_to_jewels(principal, hop_cap):
            for hop in path:
                hops.add(tuple(hop))
        for h in hops:
            usage[h] = usage.get(h, 0) + 1
    return {"usage": usage, "sampled": len(sample), "pool": len(pool)}


def snapshot(port: GraphPort, hop_cap: int = DEFAULT_HOP_CAP) -> dict[str, Any]:
    return {
        "reachability": port.reachability(hop_cap),
        "owned": port.owned_ids(),
        "jewels": port.crown_jewels(),
        "nodes": port.node_count(),
        "edges": port.edge_count(),
    }


def plan_cut_sequence(
    port: GraphPort,
    k: int = 3,
    hop_cap: int = DEFAULT_HOP_CAP,
    benign_sample_size: int = BENIGN_SAMPLE_SIZE,
    scratch_name: str | None = None,
) -> dict[str, Any]:
    """Greedy k-cut remediation PLAN with measured per-step projections.

    The whole plan is computed on a scratch COPY of the live estate
    (``port.scratch_copy(name)`` — GRAPH.COPY on the engine): each step picks
    the coverage argmax (collateral tie-break included), cuts it on the copy
    and RE-MEASURES reachability there. The live graph is never touched and
    no step ever executes here — execution is Investigator.execute_plan,
    which re-gates per step and re-measures reality, stopping at the first
    projection drift.

    Honesty contract of the returned receipts:
    - "projected_reachability" is a real measurement on the mutated copy —
      never a simulation over a frozen path set (re-routes after a cut are
      visible to it, which is exactly the point of a multi-cut plan).
    - "benign_usage" per step is re-measured on the mutated copy too: step 2
      sees the collateral of the surface that exists AFTER step 1.
    - the plan stops early when the copy measures zero ("plan_completes_at_step").
      k=3 with only 2 needed steps never invents a third.
    - "projected_verdict" mirrors interdict's verdict semantics (collapsed
      only ever on measured zero).
    """
    if k < 1:
        raise ValueError("k must be >= 1")
    copier = getattr(port, "scratch_copy", None)
    if copier is None:
        raise TypeError(
            "plan_cut_sequence requires a port with scratch_copy(name) — "
            "projections are measured on an isolated copy, never simulated"
        )
    base = snapshot(port, hop_cap)
    if base["reachability"] == 0:
        return {
            "k": k,
            "method": "graph_copy_remeasure",
            "base": {"reachability": 0, "owned": base["owned"], "jewels": base["jewels"]},
            "benign_sample_size": benign_sample_size,
            "steps": [],
            "plan_completes_at_step": None,
            "note": "surface already collapsed (0 breach paths) — nothing to plan",
        }
    name = scratch_name or f"{getattr(port, 'graph_name', 'graph')}_plan_scratch"
    scratch = copier(name)
    steps: list[dict[str, Any]] = []
    completes_at: int | None = None
    try:
        prev = base["reachability"]
        for i in range(1, k + 1):
            freq = scratch.edge_frequency(hop_cap)
            if not freq:
                break
            benign = benign_edge_usage(scratch, hop_cap, benign_sample_size)
            top = rank_cut_candidates(freq, limit=1, benign=benign["usage"])[0]
            removed = scratch.cut(top["src"], top["dst"], top["rel"])
            projected = scratch.reachability(hop_cap)
            if removed == 0:
                verdict = "no_effect"
            elif projected == 0:
                verdict = "collapsed"
            else:
                verdict = "degraded"
            steps.append({
                "step": i,
                "cut": {"src": top["src"], "rel": top["rel"], "dst": top["dst"]},
                "paths_on": top["paths_on"],
                "benign_usage": top["benign_usage"],
                "projected_reachability": projected,
                "projected_delta": projected - prev,
                "projected_verdict": verdict,
            })
            prev = projected
            if projected == 0:
                completes_at = i
                break
    finally:
        scratch.drop()
    return {
        "k": k,
        "method": "graph_copy_remeasure",
        "base": {"reachability": base["reachability"], "owned": base["owned"], "jewels": base["jewels"]},
        "benign_sample_size": benign_sample_size,
        "steps": steps,
        "plan_completes_at_step": completes_at,
        "honesty": (
            "projections are measured on an isolated GRAPH.COPY of the live "
            "estate after each cut; execution re-measures reality per step "
            "and stops at the first drift — a projected number is never the "
            "claim, the live receipt is"
        ),
    }


def interdict(
    port: GraphPort,
    src: str,
    dst: str,
    rel: str,
    hop_cap: int = DEFAULT_HOP_CAP,
) -> dict[str, Any]:
    """Execute ONE human-approved cut and return a before/after receipt."""
    before = snapshot(port, hop_cap)
    t0 = time.perf_counter()
    removed = port.cut(src, dst, rel)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    after = snapshot(port, hop_cap)
    # Verdict is a measured claim about the AFTER state of a real cut:
    #   removed == 0      -> "no_effect" (nothing was cut, nothing claimed)
    #   after == 0        -> "collapsed"  (re-measured zero breach paths)
    #   otherwise         -> "degraded"   (cut executed, >= 1 path survives)
    # audit3 pinned the two ways this was previously mislabeled: a PARTIAL
    # drop (e.g. 3 -> 1) must never claim "collapsed" — collapse is only ever
    # claimed on measured zero, never "most of the way there"; and a cut on an
    # already-collapsed surface (0 -> 0 with relationships removed) must never
    # claim "degraded" — degraded means breach paths survive. Live regression:
    # tests/test_live_interdiction_invariants.py (verdict matrix).
    if removed == 0:
        verdict = "no_effect"
    elif after["reachability"] == 0:
        verdict = "collapsed"
    else:
        verdict = "degraded"
    return {
        "cut": {"src": src, "dst": dst, "rel": rel, "relationships_removed": removed},
        "before": before,
        "after": after,
        "requery_ms": round(elapsed_ms, 2),
        "verdict": verdict,
    }
