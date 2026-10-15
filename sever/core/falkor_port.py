"""FalkorGraphPort — live FalkorDB backend. THE engine (rule 3: remove it, product breaks).

The exact Cypher SEVER depends on lives here as module constants — these are the
queries reproduced in the README's "Cypher queries" section and shown with
GRAPH.PROFILE receipts in the demo.

Live-verified on falkordb 6.0.0 (self-hosted Docker + FalkorDB Cloud).
"""
from __future__ import annotations

from typing import Any

from sever.core.jewels import (
    DEFAULT_HOP_CAP,
    cypher_traversal_pattern,
)
from sever.core.port import GraphPort
from sever.etl.ad_collectors import NormalizedGraph
from sever.etl.cypher_batches import build_batches

# ---------------------------------------------------------------------------
# The load-bearing queries (README material — cite these, PROFILE these)
# ---------------------------------------------------------------------------

JEWELS_QUERY = (
    "MATCH (g:Group) "
    "WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' "
    "RETURN g.objectid AS objectid ORDER BY objectid"
)

AZ_JEWELS_QUERY = (
    "MATCH (u:AZUser) WHERE u.name ENDS WITH '-GlobalAdministrator' "
    "RETURN u.objectid AS objectid ORDER BY objectid"
)

OWNED_QUERY = "MATCH (n {owned: true}) RETURN n.objectid AS objectid"

# FalkorDB supports shortestPath only when it terminates in WITH/RETURN, so
# reachability = per (owned, jewel) pair via PATH_QUERY_TEMPLATE — the exact
# same query paths_to_jewels uses; the agent counts owned principals with >=1
# returned path. The scripted cascade regression lives in tests/test_live.py.
REACHABILITY_METHOD = "per-pair shortestPath existence (PATH_QUERY_TEMPLATE)"

# Per-pair SHORTEST-path enumeration (ties included, capped at 100 — mirrors
# the analysis cap). FalkorDB quirk: shortestPath works only as
# a WITH-clause expression; algo.SPpaths enumerates ties but yields raw node
# ids on edges — hence the index-zip hop parser below.
PATH_QUERY_TEMPLATE = (
    "MATCH (o {{objectid: $oid}}), (t {{objectid: $target}}) "
    "CALL algo.SPpaths({{sourceNode: o, targetNode: t, pathCount: 100}}) "
    "YIELD path "
    "RETURN path"
)

CANONICAL_PATH_QUERY_TEMPLATE = (
    "MATCH (o {{objectid: $oid}}), (t {{objectid: $target}}) "
    "WITH shortestPath((o)-{pattern}->(t)) AS p "
    "RETURN p"
)

EDGE_FREQUENCY_STEP = (
    "per (owned, jewel) pair: run PATH_QUERY, walk the returned path's edges, "
    "count occurrences app-side (see sever/core/falkor_port.py)"
)

CUT_COUNT_QUERY_TEMPLATE = (
    "MATCH (s {{objectid: $src}})-[r:{rel}]->(t {{objectid: $dst}}) "
    "RETURN count(r) AS n"
)
CUT_DELETE_QUERY_TEMPLATE = (
    "MATCH (s {{objectid: $src}})-[r:{rel}]->(t {{objectid: $dst}}) "
    "DELETE r"
)

MARK_OWNED_QUERY = "MATCH (n {objectid: $oid}) SET n.owned = true"


class FalkorGraphPort(GraphPort):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        graph_name: str = "sever_demo",
        username: str | None = None,
        password: str | None = None,
        client: Any | None = None,   # injectable for tests
    ) -> None:
        if client is not None:
            self.graph = client
        else:
            from falkordb import FalkorDB

            fdb = FalkorDB(host=host, port=port, username=username, password=password)
            self.graph = fdb.select_graph(graph_name)
        self.graph_name = graph_name

    INDEXED_LABELS = (
        "User", "Group", "Computer", "Domain", "OU", "GPO", "Container",
        "CertTemplate", "EnterpriseCA", "RootCA", "AIACA", "NTAuthStore",
        "AZUser", "AZServicePrincipal", "AZApp",
    )

    # ---- load ----
    def load(self, graph: NormalizedGraph) -> None:
        for batch in build_batches(graph):
            try:
                self.graph.query(batch["query"], batch["params"])
            except Exception as exc:  # surface the exact failing batch for debugging
                rows = batch["params"].get("rows", [])
                raise RuntimeError(
                    f"batch load failed ({batch['kind']}, {len(rows)} rows): "
                    f"query={batch['query'][:120]}... "
                    f"first_row={str(rows[0])[:300] if rows else 'n/a'}"
                ) from exc
        # range indexes on the natural key — every objectid lookup becomes an
        # index scan instead of an all-node scan (see PROFILE receipts)
        for label in self.INDEXED_LABELS:
            try:
                self.graph.query(f"CREATE INDEX FOR (n:{label}) ON (n.objectid)")
            except Exception:
                pass  # already indexed

    def _scalar(self, query: str, params: dict[str, Any] | None = None, timeout_ms: int = 60000) -> Any:
        res = self.graph.query(query, params or {}, timeout=timeout_ms)
        return res.result_set[0][0] if res.result_set else None

    def node_count(self) -> int:
        return int(self._scalar("MATCH (n) RETURN count(n)"))

    def edge_count(self) -> int:
        return int(self._scalar("MATCH ()-[r]->() RETURN count(r)"))

    # ---- owned / jewels ----
    def mark_owned(self, objectid: str) -> None:
        self.graph.query(MARK_OWNED_QUERY, {"oid": objectid})

    def owned_ids(self) -> list[str]:
        res = self.graph.query(OWNED_QUERY)
        return sorted(str(row[0]) for row in res.result_set)

    def crown_jewels(self) -> list[str]:
        jewels = [str(row[0]) for row in self.graph.query(JEWELS_QUERY).result_set]
        jewels += [str(row[0]) for row in self.graph.query(AZ_JEWELS_QUERY).result_set]
        return sorted(jewels)

    # ---- traversal core ----
    def reachability(self, hop_cap: int = DEFAULT_HOP_CAP) -> int:
        jewels = self.crown_jewels()
        if not jewels:
            return 0
        query = PATH_QUERY_TEMPLATE.format(pattern=cypher_traversal_pattern(hop_cap))
        reached = 0
        for owned in self.owned_ids():
            hit = False
            for jewel in jewels:
                res = self.graph.query(query, {"oid": owned, "target": jewel}, timeout=60000)
                if res.result_set:
                    hit = True
                    break
            reached += 1 if hit else 0
        return reached

    def paths_to_jewels(
        self, objectid: str, hop_cap: int = DEFAULT_HOP_CAP, ties: bool = False
    ) -> list[list[tuple[str, str, str]]]:
        """Canonical shortest path per (principal, jewel) pair.

        ``ties=True`` switches to algo.SPpaths enumeration — the OFFLINE ANALYSIS
        mode: cross-domain tie sets explode combinatorially (measured 15-25s+ per
        pair on the sample estate), so the live demo and the agent loop use the
        canonical form (milliseconds); the ties mode exists for offline
        tie-set analysis on demand.
        """
        pattern = cypher_traversal_pattern(hop_cap)
        paths: list[list[tuple[str, str, str]]] = []
        for jewel in self.crown_jewels():
            query = (
                PATH_QUERY_TEMPLATE
                if ties
                else CANONICAL_PATH_QUERY_TEMPLATE.format(pattern=pattern)
            )
            res = self.graph.query(query, {"oid": objectid, "target": jewel}, timeout=30000)
            for row in res.result_set:
                hops = _row_to_hops(row)
                if hops:
                    paths.append(hops)
        return paths

    def edge_frequency(self, hop_cap: int = DEFAULT_HOP_CAP) -> dict[tuple[str, str, str], int]:
        freq: dict[tuple[str, str, str], int] = {}
        for owned in self.owned_ids():
            for path in self.paths_to_jewels(owned, hop_cap):
                for hop in path:
                    freq[hop] = freq.get(hop, 0) + 1
        return freq

    # ---- live mutation ----
    ADD_EDGE_QUERY = (
        "MATCH (s {{objectid: $src}}), (t {{objectid: $dst}}) "
        "MERGE (s)-[r:{rel}]->(t) "
        "SET r += $props "
        "RETURN count(r)"
    )

    def add_edge(self, src: str, dst: str, rel: str, props: dict[str, Any] | None = None) -> bool:
        if not _valid_rel(rel):
            raise ValueError(f"invalid relationship type: {rel!r}")
        query = self.ADD_EDGE_QUERY.format(rel=rel)
        created = int(self._scalar(query, {"src": src, "dst": dst, "props": props or {}}) or 0)
        return created > 0

    def cut(self, src: str, dst: str, rel: str) -> int:
        if not _valid_rel(rel):
            raise ValueError(f"invalid relationship type: {rel!r}")
        count_q = CUT_COUNT_QUERY_TEMPLATE.format(rel=rel)
        n = int(self._scalar(count_q, {"src": src, "dst": dst}))
        if n > 0:
            delete_q = CUT_DELETE_QUERY_TEMPLATE.format(rel=rel)
            self.graph.query(delete_q, {"src": src, "dst": dst})
        return n

    # ---- receipts ----
    def profile(self, query: str, params: dict[str, Any] | None = None) -> str:
        res = self.graph.client.execute_command(
            "GRAPH.PROFILE", self.graph_name, query
        )
        return str(res)

    def receipt(self) -> dict[str, Any]:
        return {
            "backend": "falkordb",
            "graph": self.graph_name,
            "nodes": self.node_count(),
            "edges": self.edge_count(),
            "owned": self.owned_ids(),
            "crown_jewels": self.crown_jewels(),
            "reachability": self.reachability(),
        }


# Relationship types are a closed vocabulary from the data model; anything else
# is rejected BEFORE it can reach string interpolation (Cypher injection guard).
_VALID_REL_RE = None


def _valid_rel(rel: str) -> bool:
    import re as _re

    global _VALID_REL_RE
    if _VALID_REL_RE is None:
        _VALID_REL_RE = _re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
    return bool(rel) and bool(_VALID_REL_RE.match(rel))


def _row_to_hops(row: Any) -> list[tuple[str, str, str]]:
    """Convert a falkordb-py Path into hop triples via index-zip.

    algo.SPpaths yields edges whose src/dest are raw node ids, so hops are
    derived from the path's ORDERED node list: nodes[i] -[edges[i]]-> nodes[i+1].
    """
    hops: list[tuple[str, str, str]] = []
    try:
        p = row[0] if isinstance(row, (list, tuple)) else row
        if p is None:
            return hops
        nodes = p.nodes() if callable(getattr(p, "nodes", None)) else p[0]
        edges = p.edges() if callable(getattr(p, "edges", None)) else p[1]
        for i, e in enumerate(edges):
            src_oid = nodes[i].properties.get("objectid", nodes[i].id)
            dst_oid = nodes[i + 1].properties.get("objectid", nodes[i + 1].id)
            hops.append((str(src_oid), str(getattr(e, "relation", "?")), str(dst_oid)))
    except Exception:
        return hops
    return hops

