"""audit3 DB-free fuzz helpers: deterministic random micro-graphs + an
independent pure-Python reachability oracle.

The oracle re-encodes the DOCUMENTED interdiction semantics from scratch —
crown jewels by SID + label (renaming-proof) with a case-INsensitive
GlobalAdministrator suffix, the closed traversal relationship set, an
inclusive hop cap, and the owned-jewel 0-hop breach — so a disagreement
between the engine's two-arm form, the per-pair probe and the oracle is
always a finding, never resolved by majority vote.

Importing this module never touches FalkorDB (generation and the oracle are
pure Python); only the live tests in tests/test_live_interdiction_invariants.py
load generated graphs onto the engine.
"""
from __future__ import annotations

import random
from collections import deque

from sever.core.jewels import TRAVERSAL_RELS, TRAVERSAL_RELS_SET
from sever.etl.ad_collectors import NormalizedGraph

GA_SUFFIX_LOWER = "-globaladministrator"

# Name suffixes the generator hands AZUser nodes: one exact-case holder (the
# sample convention) plus three case-varied REAL holders (the product
# documents case-insensitive suffix matching — a holder must not evade jewel
# detection by case) and two look-alike decoys that must NOT be jewels.
GA_NAME_POOL = (
    "-GlobalAdministrator",     # exact sample convention
    "-globaladministrator",    # case-varied holder
    "-GLOBALADMINISTRATOR",    # case-varied holder
    "-globalAdministratoR",    # case-varied holder
    "-globaladministrators",  # trailing s: NOT a holder
    "-xglobaladministrator",  # missing hyphen: NOT a holder
)

# deliberately NON-traversable rels mixed into fuzz graphs (ENROLL is in the
# abusable vocabulary but excluded from TRAVERSAL_RELS on purpose — fuzz must
# prove neither reachability form chains it)
NON_TRAVERSAL_RELS = ("CONTAINED_BY", "PUBLISHED_ON", "ENROLL")


class MicroGraph:
    """A deterministic random graph spec + its owned set + optional self-loop."""

    def __init__(
        self,
        graph: NormalizedGraph,
        nodes: dict[str, tuple[str, str]],
        edges: list[tuple[str, str, str]],
        owned: list[str],
        self_loop_oid: str | None,
    ) -> None:
        self.graph = graph          # ready for FalkorGraphPort.load()
        self.nodes = nodes          # oid -> (label, name)
        self.edges = edges          # [(src, rel, dst), ...] as loaded
        self.owned = owned          # oids to mark_owned
        self.self_loop_oid = self_loop_oid  # raw self-loop to inject post-load


def oracle_jewels(nodes: dict[str, tuple[str, str]]) -> set[str]:
    """Documented crown-jewel rule, re-encoded independently of the Cypher."""
    out: set[str] = set()
    for oid, (label, name) in nodes.items():
        if label == "Group" and (oid.endswith("-512") or oid.endswith("-519")):
            out.add(oid)
        elif label == "AZUser" and str(name).lower().endswith(GA_SUFFIX_LOWER):
            out.add(oid)
    return out


def oracle_reached(
    nodes: dict[str, tuple[str, str]],
    edges: list[tuple[str, str, str]],
    owned,
    hop_cap: int = 12,
) -> set[str]:
    """Owned principals that are jewels (0-hop breach) or have a 1..hop_cap
    edge traversal chain over TRAVERSAL_RELS to any jewel (BFS, DB-free)."""
    jewels = oracle_jewels(nodes)
    adj: dict[str, set[str]] = {}
    for s, rel, d in edges:
        if rel in TRAVERSAL_RELS_SET:
            adj.setdefault(s, set()).add(d)
    owned_set = set(owned)
    reached = owned_set & jewels
    for o in owned_set - jewels:
        seen = {o}
        queue: deque[tuple[str, int]] = deque([(o, 0)])
        while queue:
            cur, depth = queue.popleft()
            if depth >= hop_cap:
                continue
            for nxt in adj.get(cur, ()):
                if nxt in jewels:
                    reached.add(o)
                    queue.clear()
                    break
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, depth + 1))
    return reached


def random_micro_graph(rng: random.Random, tag: str) -> MicroGraph:
    """One random small graph (2-8 nodes, random abusable rels, random owned).

    Deterministic in `rng`; the audit pins seeds 0..49.
    """
    n = rng.randint(2, 8)
    g = NormalizedGraph()
    nodes: dict[str, tuple[str, str]] = {}
    labels = ("User", "User", "User", "Group", "AZUser", "AZUser")
    force_ga_holder = rng.random() < 0.25  # exercise the GA suffix rule often
    for i in range(n):
        label = "AZUser" if (i == 0 and force_ga_holder) else rng.choice(labels)
        name = f"node{i}"
        oid = f"audit3-{tag}-{i}"
        if label == "Group" and rng.random() < 0.30:
            oid += rng.choice(("-512", "-519"))  # jewel by SID regardless of name
        if label == "AZUser" and rng.random() < 0.45:
            name += rng.choice(GA_NAME_POOL)
        g.add_node(oid, label, {"name": name})
        nodes[oid] = (label, name)

    oids = list(nodes)
    edges: list[tuple[str, str, str]] = []
    max_edges = n * (n - 1)
    m = rng.randint(0, min(3 * n, max_edges))
    for _ in range(m):
        s, d = rng.sample(oids, 2)
        rel = rng.choice(TRAVERSAL_RELS) if rng.random() < 0.75 else rng.choice(NON_TRAVERSAL_RELS)
        if g.add_edge(s, d, rel, {"source": f"audit3-{tag}"}):
            edges.append((s, rel, d))

    roll = rng.random()
    if roll < 0.10:
        owned: list[str] = []           # nobody compromised
    elif roll < 0.25:
        owned = list(nodes)             # EVERY node compromised
    else:
        owned = rng.sample(oids, rng.randint(1, n))

    # ~20% of graphs get a raw self-loop injected after load (the sanctioned
    # ingest paths reject self-edges; the reachability forms must still be
    # well-behaved if one exists in the substrate)
    self_loop_oid = rng.choice(oids) if rng.random() < 0.20 else None
    return MicroGraph(g, nodes, edges, owned, self_loop_oid)
