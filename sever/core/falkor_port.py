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

REACH_QUERY_TEMPLATE = (
    "MATCH (o {{owned: true}}) "
    "MATCH (t) WHERE t.objectid IN $jewels "
    "MATCH p = shortestPath((o)-{pattern}->(t)) "
    "RETURN count(DISTINCT o) AS reachable"
)

PATH_QUERY_TEMPLATE = (
    "MATCH p = shortestPath("
    "(o {{objectid: $oid}})-{pattern}->(t {{objectid: $target}})) "
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
        query = REACH_QUERY_TEMPLATE.format(pattern=cypher_traversal_pattern(hop_cap))
        return int(self._scalar(query, {"jewels": self.crown_jewels()}))

    def paths_to_jewels(self, objectid: str, hop_cap: int = DEFAULT_HOP_CAP) -> list[list[tuple[str, str, str]]]:
        pattern = cypher_traversal_pattern(hop_cap)
        paths: list[list[tuple[str, str, str]]] = []
        for jewel in self.crown_jewels():
            query = PATH_QUERY_TEMPLATE.format(pattern=pattern)
            res = self.graph.query(query, {"oid": objectid, "target": jewel}, timeout=60000)
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
        "MATCH (s {objectid: $src}), (t {objectid: $dst}) "
        "MERGE (s)-[r:{rel}]->(t) "
        "SET r += $props "
        "RETURN count(r)"
    )

    def add_edge(self, src: str, dst: str, rel: str, props: dict[str, Any] | None = None) -> bool:
        query = self.ADD_EDGE_QUERY.format(rel=rel)
        created = int(self._scalar(query, {"src": src, "dst": dst, "props": props or {}}) or 0)
        return created > 0

    def cut(self, src: str, dst: str, rel: str) -> int:
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


def _row_to_hops(row: Any) -> list[tuple[str, str, str]]:
    """Convert a returned path object (nodes, edges collections) into hop triples.

    falkordb-py returns paths as (nodes, edges, indices); be defensive — verified
    against the live instance, adjusted if the wire format differs.
    """
    hops: list[tuple[str, str, str]] = []
    try:
        nodes, edges, _ = row if isinstance(row, tuple) else (row.nodes, row.edges, None)
        for e in edges:
            hops.append((str(e.src_node.objectid if hasattr(e, "src_node") else e[0]),
                         str(getattr(e, "relation", e[1] if len(e) > 1 else "")),
                         str(e.dest_node.objectid if hasattr(e, "dest_node") else e[2])))
    except Exception:
        return hops
    return hops
