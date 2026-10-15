"""Interdiction scoring — edge ranking, greedy k-cut, receipts.

Math honesty (README material):
- Frequency is coverage of the ENUMERATED paths: exactly one canonical
  shortest path per (owned, jewel) pair (ties off by default), so
  "paths_on" counts pair-coverage, not all possible routes.
- k=1: the max-frequency edge is the exact argmax of enumerated-path
  coverage (trivially — frequency IS that count). It still may not collapse
  reachability: alternative or tied routes survive the cut, and the
  receipt reports that honestly ("DEGRADED", never a silent success).
- k>1: each round re-enumerates paths on the MUTATED graph and again picks
  the exact single-edge coverage argmax. This is greedy-RANKED, not an
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
- "Kills most paths (N of M)" — never "all paths" unless re-measured to zero.
"""
from __future__ import annotations

import time
from typing import Any

from sever.core.jewels import DEFAULT_HOP_CAP
from sever.core.port import GraphPort


def rank_cut_candidates(
    freq: dict[tuple[str, str, str], int], limit: int = 10
) -> list[dict[str, Any]]:
    """Edge-frequency ranking — the agent's remediation proposal list."""
    ranked = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return [
        {"src": s, "rel": r, "dst": d, "paths_on": c}
        for (s, r, d), c in ranked
    ]


def snapshot(port: GraphPort, hop_cap: int = DEFAULT_HOP_CAP) -> dict[str, Any]:
    return {
        "reachability": port.reachability(hop_cap),
        "owned": port.owned_ids(),
        "jewels": port.crown_jewels(),
        "nodes": port.node_count(),
        "edges": port.edge_count(),
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
    return {
        "cut": {"src": src, "dst": dst, "rel": rel, "relationships_removed": removed},
        "before": before,
        "after": after,
        "requery_ms": round(elapsed_ms, 2),
        "verdict": "collapsed" if after["reachability"] < before["reachability"] else "degraded" if after["reachability"] == before["reachability"] and removed else "no_effect",
    }
