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
    TRAVERSAL_RELS,
    TRAVERSAL_RELS_SET,
    cypher_traversal_pattern,
)
from sever.core.port import GraphPort
from sever.etl.ad_collectors import ABUSABLE_RELS, NormalizedGraph
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
    "MATCH (u:AZUser) WHERE toLower(u.name) ENDS WITH '-globaladministrator' "
    "RETURN u.objectid AS objectid ORDER BY objectid"
)

OWNED_QUERY = "MATCH (n {owned: true}) RETURN n.objectid AS objectid"

# FalkorDB supports shortestPath only when it terminates in WITH/RETURN, so
# reachability = per (owned, jewel) pair via REACHABILITY_QUERY_TEMPLATE — the
# same traversal pattern (relationship filter + hop cap) the canonical
# enumeration in paths_to_jewels uses. The scripted cascade regression lives
# in tests/test_live.py; the boundary/edge-case matrix in
# tests/test_live_semantics.py.
REACHABILITY_METHOD = (
    "two-arm all-pairs shortestPath existence (REACHABILITY_ARM_TEMPLATES) "
    "with the traversal relationship filter and hop cap of paths_to_jewels; "
    "an owned principal that is itself a crown jewel counts as reached "
    "(0-hop breach)"
)

# The two reachability arms: shortestPath is evaluated per (owned, jewel) row
# inside the WITH clause (FalkorDB's only valid shortestPath form), `WHERE p IS
# NOT NULL` keeps reached pairs, DISTINCT collapses to the reached-principal
# set; the Group and AZUser arms union in Python because crown jewels span two
# labels. O(2) queries instead of O(owned x jewels) — the same semantics as
# the per-pair form (pattern + hop cap), measured ~8x faster end-to-end and
# immune to SPpaths' combinatorial tie-enumeration hang (which the per-pair
# SPpaths form exposed on reachable non-jewel pairs). Recovered + adapted from
# the audit2/perf-reliability agent (gateway-interrupted mid-verification).
#
# Each arm's target predicate MUST mirror the matching crown_jewels() query
# exactly. The AZ arm uses toLower(...) ENDS WITH '-globaladministrator' like
# AZ_JEWELS_QUERY: the product documents case-insensitive GA-suffix matching
# (a holder named jdoe-GLOBALADMINISTRATOR is still a jewel, not an evasion).
# audit3 found the arm originally matched the suffix case-SENSITIVELY, so it
# silently undercounted breaches — a principal with a path to a case-varied
# GA holder was reported unreachable by reachability() while paths_to_jewels()
# and the per-pair form both saw it (live-pinned in
# tests/test_live_interdiction_invariants.py).
REACHABILITY_ARM_TEMPLATES: tuple[str, ...] = (
    (
        "MATCH (o {{owned: true}}), (t:Group) "
        "WHERE t.objectid ENDS WITH '-512' OR t.objectid ENDS WITH '-519' "
        "WITH o, t, shortestPath((o)-{pattern}->(t)) AS p "
        "WHERE p IS NOT NULL "
        "RETURN DISTINCT o.objectid AS oid"
    ),
    (
        "MATCH (o {{owned: true}}), (t:AZUser) "
        "WHERE toLower(t.name) ENDS WITH '-globaladministrator' "
        "WITH o, t, shortestPath((o)-{pattern}->(t)) AS p "
        "WHERE p IS NOT NULL "
        "RETURN DISTINCT o.objectid AS oid"
    ),
)

# Existence probe: shortestPath yields NULL when no bounded traversal path
# exists, so the row's `hit` is false rather than the result being empty
# (live-verified on falkordb 6.0.0).
REACHABILITY_QUERY_TEMPLATE = (
    "MATCH (o {{objectid: $oid}}), (t {{objectid: $target}}) "
    "WITH shortestPath((o)-{pattern}->(t)) AS p "
    "RETURN p IS NOT NULL AS hit"
)

# Per-pair SHORTEST-path tie enumeration (offline analysis mode, capped at
# 100 paths). FalkorDB quirk: shortestPath works only as a WITH-clause
# expression; algo.SPpaths enumerates ties but yields raw node ids on edges —
# hence the index-zip hop parser below. The traversal set is passed server-side
# via `relTypes` (live-verified honored: a CONTAINED_BY-only pair returns 0
# rows under relTypes ['MEMBER_OF']) and re-enforced app-side, because SPpaths
# has NO working hop-bound config on falkordb 6.0.0 — unknown config keys such
# as `maxHops` are accepted and silently ignored (a 12-hop path is returned
# even under maxHops: 2), so the hop cap is applied to the parsed hops.
# Observed on a shared engine under concurrent graph create/delete churn: the
# procedure can intermittently fail server-side ("unhandled type in inlined
# properties") — one more reason the live loop and the reachability metric use
# only the canonical shortestPath form.
PATH_QUERY_TEMPLATE = (
    "MATCH (o {{objectid: $oid}}), (t {{objectid: $target}}) "
    "CALL algo.SPpaths({{sourceNode: o, targetNode: t, relTypes: "
    + "[" + ", ".join("'" + r + "'" for r in TRAVERSAL_RELS) + "]"
    + ", pathCount: 100}}) "
    "YIELD path "
    "RETURN path"
)

CANONICAL_PATH_QUERY_TEMPLATE = (
    "MATCH (o {{objectid: $oid}}), (t {{objectid: $target}}) "
    "WITH shortestPath((o)-{pattern}->(t)) AS p "
    "RETURN p"
)

EDGE_FREQUENCY_STEP = (
    "per (owned, jewel) pair: run the CANONICAL shortest-path query, walk the "
    "returned path's edges, count occurrences app-side (see "
    "sever/core/falkor_port.py)"
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

# Principals that can hold (possibly legitimate) access flows — the pool the
# benign-usage/collateral estimate samples over (sever/core/scoring.py).
USER_OBJECTIDS_QUERY = "MATCH (u:User) RETURN u.objectid AS objectid ORDER BY objectid"


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

    def user_objectids(self) -> list[str]:
        """All User principals of the loaded estate, deterministic order —
        the sampling pool for the benign-usage (cut collateral) estimate."""
        res = self.graph.query(USER_OBJECTIDS_QUERY)
        return sorted(str(row[0]) for row in res.result_set)

    # ---- isolated-copy projection substrate ----
    # The multi-cut PLAN (scoring.plan_cut_sequence) projects each step on a
    # scratch copy of the live estate so the live graph is never mutated by a
    # proposal. GRAPH.COPY is a server-side, engine-native copy — the same
    # engine that answers live queries answers the projections (live-verified
    # on falkordb 6.0.0; copy of the 1480-node/12450-edge sample estate
    # measures ~0.1s).
    def scratch_copy(self, scratch_name: str) -> "FalkorGraphPort":
        """Return a port on a fresh isolated copy of THIS graph.

        Idempotent like every other graph lifecycle path: an existing
        destination key is deleted first, mirroring make_live_port's
        hermetic-start rule (a leftover scratch from a crashed run must
        never be silently re-used and serve stale state into a plan).
        """
        from falkordb import Graph as _Graph

        client = self.graph.client
        try:
            client.execute_command("GRAPH.DELETE", scratch_name)
        except Exception:
            pass  # no such key — the normal case
        client.execute_command("GRAPH.COPY", self.graph_name, scratch_name)
        return FalkorGraphPort(
            client=_Graph(client=client, name=scratch_name),
            graph_name=scratch_name,
        )

    def drop(self) -> None:
        """Delete this port's graph key idempotently. Terminal for the port —
        the plan projection's scratch graphs are dropped in a ``finally`` so
        a crashed plan can never leak a scratch estate on the engine."""
        try:
            self.graph.client.execute_command("GRAPH.DELETE", self.graph_name)
        except Exception:
            pass

    def crown_jewels(self) -> list[str]:
        jewels = [str(row[0]) for row in self.graph.query(JEWELS_QUERY).result_set]
        jewels += [str(row[0]) for row in self.graph.query(AZ_JEWELS_QUERY).result_set]
        return sorted(jewels)

    # ---- traversal core ----
    def reachability(self, hop_cap: int = DEFAULT_HOP_CAP) -> int:
        # two-arm all-pairs form: identical semantics to the per-pair
        # canonical probe (pattern + hop cap), but shortestPath is evaluated
        # per (owned, jewel) row inside WITH — O(2) queries instead of
        # O(owned x jewels). Self-pairs (an owned crown jewel = the breach
        # itself, 0 hops) are invisible to shortestPath, so owned jewels are
        # counted directly.
        reached: set[str] = set()
        pattern = cypher_traversal_pattern(hop_cap)
        for arm in REACHABILITY_ARM_TEMPLATES:
            res = self.graph.query(arm.format(pattern=pattern), timeout=60000)
            reached.update(str(row[0]) for row in res.result_set)
        jewel_set = set(self.crown_jewels())
        reached.update(o for o in self.owned_ids() if o in jewel_set)
        return len(reached)

    def paths_to_jewels(
        self, objectid: str, hop_cap: int = DEFAULT_HOP_CAP, ties: bool = False
    ) -> list[list[tuple[str, str, str]]]:
        """Canonical shortest path per (principal, jewel) pair.

        ``ties=True`` switches to algo.SPpaths enumeration — the OFFLINE ANALYSIS
        mode: cross-domain tie sets explode combinatorially (measured 15-25s+ per
        pair on the sample estate), so the live demo and the agent loop use the
        canonical form (milliseconds); the ties mode exists for offline
        tie-set analysis on demand. SPpaths walks unbounded paths even with the
        server-side ``relTypes`` filter (there is no working hop-bound config on
        falkordb 6.0.0), so returned paths are re-enforced app-side against the
        traversal set and the hop cap — offline analysis can never report a
        structural (CONTAINED_BY/PUBLISHED_ON) or over-long hop as an attack hop.
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
                if not hops:
                    continue
                # hop-cap + traversal-set guard (no-op for the canonical form,
                # which is engine-enforced; load-bearing for the ties form)
                if len(hops) > hop_cap or any(
                    rel not in TRAVERSAL_RELS_SET for _, rel, _ in hops
                ):
                    continue
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
    # `RETURN pre` (count of the edge BEFORE the MERGE) is what makes add_edge
    # contract-true: `RETURN count(r)` after MERGE is 1 whether the edge was
    # created or already existed, so it could never report idempotent re-grants
    # (live-verified on falkordb 6.0.0).
    ADD_EDGE_QUERY = (
        "MATCH (s {{objectid: $src}}), (t {{objectid: $dst}}) "
        "OPTIONAL MATCH (s)-[r0:{rel}]->(t) "
        "WITH s, t, count(r0) AS pre "
        "MERGE (s)-[r:{rel}]->(t) "
        "SET r += $props "
        "RETURN pre"
    )

    def add_edge(self, src: str, dst: str, rel: str, props: dict[str, Any] | None = None) -> bool:
        if src == dst:
            # a self-referencing grant is meaningless and the ETL contract
            # rejects it (NormalizedGraph.add_edge returns False on src==dst) —
            # live mutations must not smuggle in what ingest refuses
            return False
        if not _valid_rel(rel):
            raise ValueError(f"invalid relationship type: {rel!r}")
        query = self.ADD_EDGE_QUERY.format(rel=rel)
        pre = self._scalar(query, {"src": src, "dst": dst, "props": props or {}})
        # pre is None when an endpoint is absent (no rows) — nothing created.
        # pre == 0 means the edge did not exist before, i.e. MERGE created it.
        return pre is not None and int(pre) == 0

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
        # GRAPH.PROFILE needs the CYPHER params header in the query string —
        # the client builds it for graph.query/profile, so reuse its builder
        # but keep the RAW response (the wrapped ExecutionPlan drops ms
        # timings, and the ms numbers are the point of profile receipts).
        q = self.graph._build_params_header(params) + query
        res = self.graph.client.execute_command(
            "GRAPH.PROFILE", self.graph_name, q
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
        # \Z (not $): Python's $ also matches before a trailing newline, which
        # would let a trailing-newline rel through (audit/security regression test).
        _VALID_REL_RE = _re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}\Z")
    if not rel or not _VALID_REL_RE.match(rel):
        return False
    # schema guard: identifier-shaped is not enough — mutations only accept
    # rels in the closed vocabulary the ETL emits and the engine chains
    # (so "generic_all" and other unknown-but-well-formed types reject).
    return rel in TRAVERSAL_RELS_SET or rel in ABUSABLE_RELS


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

