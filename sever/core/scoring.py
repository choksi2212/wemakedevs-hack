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
- Measurement FORM (audit7/perf-scoring): the plan measures each state —
  base and every post-cut projection — with the per-(owned, jewel) canonical
  enumeration it already performs for edge scoring, plus the same owned-
  jewel 0-hop union reachability() applies. That per-pair form evaluates the
  SAME traversal pattern + hop cap the two-arm reachability query evaluates
  per (owned, jewel) row, so it is the same measurement in a different form
  (pinned arm == per-pair == DB-free oracle in
  tests/test_live_interdiction_invariants.py, and old-vs-new receipts in
  tests/test_perf_equivalence.py). It removes the all-pairs arm query —
  the 2-4s-per-traversal query on the multi-tenant cloud engine that made a
  k=3 plan take 13-14s — while still re-measuring the mutated copy after
  every cut: the enumeration is fresh at every step, nothing is carried
  over from a pre-cut state.

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

import os
import time
from typing import Any

from sever.core.jewels import DEFAULT_HOP_CAP
from sever.core.port import GraphPort

# How many non-owned principals are sampled for the benign-usage (collateral)
# estimate. Sampling is deterministic (sorted objectids, even stride), so the
# same estate always receipts the same numbers — replay-identical like every
# other SEVER artifact.
BENIGN_SAMPLE_SIZE = 25


def _multi_canonical_paths(
    port: Any,
    objectids: list[str],
    hop_cap: int,
    jewels: list[str] | None = None,
) -> dict[str, list[list[tuple[str, str, str]]]]:
    """Seam accessor with the pre-audit7 fallback: a port that HAS
    canonical_paths_multi (every GraphPort subclass) gets the one-call
    enumeration; a duck-typed port without it falls back to the
    per-principal paths_to_jewels loop — identical numbers, identical
    per-pair semantics (it is the same loop the ABC default runs)."""
    multi = getattr(port, "canonical_paths_multi", None)
    if multi is not None:
        return multi(objectids, hop_cap, jewels)
    return {oid: port.paths_to_jewels(oid, hop_cap) for oid in objectids}


def _enumeration_frequency(
    paths_by_owned: dict[str, list[list[tuple[str, str, str]]]],
) -> dict[tuple[str, str, str], int]:
    """Per-edge occurrence count across the enumerated canonical paths —
    the same count ``port.edge_frequency()`` computes from the same
    enumeration (audit7: the plan owns its enumeration so ONE pass feeds
    both the edge scoring and the reachability projection)."""
    freq: dict[tuple[str, str, str], int] = {}
    for paths in paths_by_owned.values():
        for path in paths:
            for hop in path:
                freq[hop] = freq.get(hop, 0) + 1
    return freq


def _reached_principals(
    paths_by_owned: dict[str, list[list[tuple[str, str, str]]]],
    owned: list[str],
    jewel_set: set[str],
) -> set[str]:
    """The reachability SET behind the headline count, derived from the
    per-(owned, jewel) canonical enumeration.

    Equivalent to the port's ``reachability()`` on the same graph state: the
    canonical per-pair probe evaluates the same traversal pattern + hop cap
    the two-arm reachability query evaluates per (owned, jewel) row (pinned
    arm == per-pair == DB-free oracle in tests/test_live_interdiction_
    invariants.py), and the owned-jewel union below is the same 0-hop breach
    term ``FalkorGraphPort.reachability`` applies. An owned principal with
    at least one enumerated path is its own witness — edge removal can never
    un-reach it, and can never reach more — so this is a measurement of the
    state it is handed, never a projection across states.
    """
    reached = {oid for oid, paths in paths_by_owned.items() if paths}
    return reached | (set(owned) & jewel_set)


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
    # ONE enumeration call for the whole sample (audit7/perf-scoring): the
    # ABC's canonical_paths_multi defaults to the per-principal
    # paths_to_jewels loop (identical queries + identical numbers), and a
    # backend override batches the same per-pair canonical probes into a
    # single UNWIND query — the per-principal round-trips were the cloud
    # plan's dominant cost after the arm queries.
    for principal, paths in _multi_canonical_paths(port, sample, hop_cap).items():
        hops: set[tuple[str, str, str]] = set()
        for path in paths:
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
      visible to it, which is exactly the point of a multi-cut plan). The
      measurement re-enumerates the post-cut copy per (owned, jewel) pair —
      the per-pair form of the same traversal the two-arm reachability
      query evaluates (pinned equivalent in
      tests/test_live_interdiction_invariants.py; old-vs-new receipts in
      tests/test_perf_equivalence.py) — and the base number is measured on
      the same isolated copy, so one receipt speaks about one estate state.
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
    # UNIQUE scratch key per invocation (audit5/multi-client): the fixed
    # ``{graph}_plan_scratch`` name made two concurrent planners share ONE
    # engine-side copy — one planner's GRAPH.DELETE/COPY churn landed under the
    # other's mid-plan measurements, serving contaminated projections to the
    # human gate (all-steps-no_effect plans, wrong plan_completes_at_step) or
    # bare 500s (measured 3/8 concurrent planners, audit5/multi-client). The
    # recognizable ``{graph}_plan_scratch_`` prefix is kept so a key leaked by
    # a crashed process stays identifiable and cleanable; the ``finally``
    # drop() still removes it on every normal path.
    name = scratch_name or (
        f"{getattr(port, 'graph_name', 'graph')}_plan_scratch_{os.urandom(4).hex()}"
    )
    scratch = copier(name)
    steps: list[dict[str, Any]] = []
    completes_at: int | None = None
    try:
        # All numbers — base AND every per-step projection — are measured on
        # the isolated copy (the copy IS the snapshot the plan reasons about;
        # measuring the base there keeps every number in one receipt from one
        # consistent estate state instead of straddling a live read and a
        # copy). One enumeration per state feeds BOTH the edge scoring and
        # the reachability projection (see _reached_principals): the plan
        # re-enumerates the mutated copy after every cut, so re-routes stay
        # visible — the arm-query FORM of reachability is replaced by the
        # pinned-equivalent per-pair form, not the re-measurement.
        owned = scratch.owned_ids()
        jewels = scratch.crown_jewels()
        jewel_set = set(jewels)
        paths_by_owned = _multi_canonical_paths(scratch, owned, hop_cap, jewels)
        base_reach = len(_reached_principals(paths_by_owned, owned, jewel_set))
        if base_reach == 0:
            return {
                "k": k,
                "method": "graph_copy_remeasure",
                "base": {"reachability": 0, "owned": owned, "jewels": jewels},
                "benign_sample_size": benign_sample_size,
                "steps": [],
                "plan_completes_at_step": None,
                "note": "surface already collapsed (0 breach paths) — nothing to plan",
            }
        prev = base_reach
        for i in range(1, k + 1):
            freq = _enumeration_frequency(paths_by_owned)
            if not freq:
                break
            benign = benign_edge_usage(scratch, hop_cap, benign_sample_size)
            top = rank_cut_candidates(freq, limit=1, benign=benign["usage"])[0]
            removed = scratch.cut(top["src"], top["dst"], top["rel"])
            # fresh enumeration of the MUTATED copy = the post-cut measurement
            paths_by_owned = _multi_canonical_paths(scratch, owned, hop_cap, jewels)
            projected = len(_reached_principals(paths_by_owned, owned, jewel_set))
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
        "base": {"reachability": base_reach, "owned": owned, "jewels": jewels},
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
