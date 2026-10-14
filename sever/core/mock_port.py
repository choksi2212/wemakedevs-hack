"""In-memory GraphPort — networkx-backed engine for offline development + tests.

Semantics mirror FalkorGraphPort exactly:
- reachability = any abusable chain within the hop cap (BFS, O(V+E) per owned node)
- paths       = SHORTEST paths per (owned, jewel) pair — same as FalkorDB's
                shortestPath — bounded by MAX_PATHS_PER_PAIR
"""
from __future__ import annotations

import json
from itertools import islice
from typing import Any

import networkx as nx

from sever.core.jewels import (
    DEFAULT_HOP_CAP,
    TRAVERSAL_RELS_SET,
    cypher_traversal_pattern,
    is_crown_jewel,
)
from sever.core.port import GraphPort
from sever.etl.ad_collectors import NormalizedGraph

MAX_PATHS_PER_PAIR = 100


class MockGraphPort(GraphPort):
    def __init__(self) -> None:
        self.g: nx.MultiDiGraph = nx.MultiDiGraph()
        self._projection: nx.DiGraph | None = None
        self._rels: dict[tuple[str, str], set[str]] = {}

    # ---- internal: abusable-edge projection ----
    def _invalidate(self) -> None:
        self._projection = None
        self._rels = {}

    def _attack(self) -> nx.DiGraph:
        if self._projection is None:
            p = nx.DiGraph()
            for u, v, data in self.g.edges(data=True):
                if data.get("rel") in TRAVERSAL_RELS_SET:
                    if not p.has_edge(u, v):
                        p.add_edge(u, v)
                        self._rels[(u, v)] = set()
                    self._rels[(u, v)].add(data["rel"])
            self._projection = p
        return self._projection

    def _rel_between(self, u: str, v: str) -> str:
        rels = self._rels.get((u, v), set())
        return sorted(rels)[0] if rels else "RELATED"

    # ---- load ----
    def load(self, graph: NormalizedGraph) -> None:
        for oid, node in graph.nodes.items():
            self.g.add_node(oid, label=node["label"], props=node["props"])
        for e in graph.edges.values():
            self.g.add_edge(e["src"], e["dst"], key=f"{e['rel']}|{e['props']}", rel=e["rel"], props=e["props"])
        self._invalidate()

    def node_count(self) -> int:
        return self.g.number_of_nodes()

    def edge_count(self) -> int:
        return self.g.number_of_edges()

    # ---- owned / jewels ----
    def mark_owned(self, objectid: str) -> None:
        if objectid in self.g:
            self.g.nodes[objectid]["props"]["owned"] = True

    def owned_ids(self) -> list[str]:
        return sorted(
            n for n, d in self.g.nodes(data=True)
            if d.get("props", {}).get("owned")
        )

    def crown_jewels(self) -> list[str]:
        return sorted(
            n for n, d in self.g.nodes(data=True)
            if d.get("label") == "Group" and is_crown_jewel(n)
        )

    # ---- traversal core ----
    def _reachable_within(self, start: str, targets: set[str], hop_cap: int) -> bool:
        p = self._attack()
        if start in targets:
            return True
        if start not in p:
            return False  # isolated node (e.g. after its only edge was cut)
        dist = nx.single_source_shortest_path_length(p, start, cutoff=hop_cap)
        return any(t in dist for t in targets)

    def reachability(self, hop_cap: int = DEFAULT_HOP_CAP) -> int:
        jewels = set(self.crown_jewels())
        return sum(1 for o in self.owned_ids() if self._reachable_within(o, jewels, hop_cap))

    def paths_to_jewels(self, objectid: str, hop_cap: int = DEFAULT_HOP_CAP) -> list[list[tuple[str, str, str]]]:
        p = self._attack()
        jewels = set(self.crown_jewels())
        out: list[list[tuple[str, str, str]]] = []
        for jewel in sorted(jewels):
            if not p.has_node(objectid) or not p.has_node(jewel):
                continue
            try:
                dist = nx.shortest_path_length(p, objectid, jewel)
            except nx.NetworkXNoPath:
                continue
            if dist > hop_cap:
                continue
            for sp in islice(nx.all_shortest_paths(p, objectid, jewel), MAX_PATHS_PER_PAIR):
                hops: list[tuple[str, str, str]] = []
                for u, v in zip(sp, sp[1:]):
                    hops.append((u, self._rel_between(u, v), v))
                out.append(hops)
        return out

    def edge_frequency(self, hop_cap: int = DEFAULT_HOP_CAP) -> dict[tuple[str, str, str], int]:
        freq: dict[tuple[str, str, str], int] = {}
        for owned in self.owned_ids():
            for path in self.paths_to_jewels(owned, hop_cap):
                for hop in path:
                    freq[hop] = freq.get(hop, 0) + 1
        return freq

    # ---- live mutation ----
    def add_edge(self, src: str, dst: str, rel: str, props: dict[str, Any] | None = None) -> bool:
        """Grant a new edge (finding application). Idempotent via props-key dedupe."""
        key = f"{rel}|{json.dumps(props or {}, sort_keys=True, default=str)}"
        if src not in self.g or dst not in self.g or self.g.has_edge(src, dst, key=key):
            return False
        self.g.add_edge(src, dst, key=key, rel=rel, props=props or {})
        if rel in TRAVERSAL_RELS_SET:
            self._invalidate()
        return True

    def cut(self, src: str, dst: str, rel: str) -> int:
        """Remove every prop-variant of src-[rel]->dst. Returns count removed."""
        removed = 0
        for _, d, k, data in list(self.g.out_edges(src, keys=True, data=True)):
            if d == dst and data.get("rel") == rel:
                self.g.remove_edge(src, dst, key=k)
                removed += 1
        if removed:
            self._invalidate()
        return removed

    # ---- receipts ----
    def profile(self, query: str, params: dict[str, Any] | None = None) -> str:
        return f"[mock-port] offline mode; traversal pattern: {cypher_traversal_pattern()}"

    def receipt(self) -> dict[str, Any]:
        return {
            "backend": "mock",
            "nodes": self.node_count(),
            "edges": self.edge_count(),
            "owned": self.owned_ids(),
            "crown_jewels": self.crown_jewels(),
            "reachability": self.reachability(),
        }
