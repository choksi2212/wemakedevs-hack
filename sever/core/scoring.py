"""Interdiction scoring — edge ranking, greedy k-cut, receipts.

Math honesty (README material):
- k=1: choosing the max path-frequency edge is the exact argmax of "paths
  destroyed" when the candidate set is restricted to edges on enumerated
  shortest paths (path-coverage form of the critical-edge problem).
- k>1: greedy path-coverage maximization — submodular, so it carries the
  classic (1 - 1/e) approximation guarantee. We say "greedy-ranked", never
  "optimal": optimal multi-edge interdiction is NP-hard (Israeli & Wood 2002;
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
