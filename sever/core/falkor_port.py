"""FalkorGraphPort — live FalkorDB backend. THE engine (rule 3: remove it, product breaks).

The exact Cypher SEVER depends on lives here as module constants — these are the
queries reproduced in the README's "Cypher queries" section and shown with
GRAPH.PROFILE receipts in the demo.

Live-verified on falkordb 6.0.0 (self-hosted Docker) and on the managed
FalkorDB Cloud instance (module 'graph' 4.22.0 — see
docs/receipts/receipts_cloud_live.json and audit5_cloud_instance.json).

audit7/perf-client — round-trip folds (every engine call on the Cloud is a
WAN hop + free-tier CPU; redundant queries are pure latency):

- ESTATE_SNAPSHOT_QUERY folds the SIX accessor queries /api/state used to
  issue per poll (node count, edge count, owned list, AD jewels, AZ jewels,
  and the second owned re-read) into ONE statement; the two-arm reachability
  stays byte-identical (REACHABILITY_ARM_TEMPLATES) and runs the two arms
  CONCURRENTLY on the connection pool (they're independent read queries).
  /api/state: 11 sequential round-trips -> 3. Every accessor still returns
  exactly what its documented single-purpose query returned — pinned by
  tests/test_perf_client_folds.py against independent legacy re-queries on
  the real engine.
- The fold activates only on a REAL falkordb client (the injected-client
  stubs used by the DB-free wire-shape tests keep the exact legacy
  per-query call sequence — those tests pin the wire contracts of each
  individual query) and only while the engine accepts the combined form:
  the first engine-side REJECTION of a folded query permanently downgrades
  the port to the legacy per-query forms (honest capability fallback — a
  slow-but-successful query NEVER triggers it, so engine slowness is never
  masked; there are no retries anywhere in this module). The cross-product
  shortestPath folds (paths batch, edge-frequency batch, all-owned arms)
  additionally require falkordb >= 6.0.0 (probed once via MODULE LIST):
  on older engines (the managed Cloud 4.22.0) those cross forms compute
  shortestPath for a single row of a multi-row binding and UNDERCOUNT —
  live-verified: the shipped all-owned reachability arm returned ZERO
  reachable ids for 2 owned principals where the per-pair probe sees one
  (a live-prod correctness bug this change also fixes: reachability now
  uses the per-owned arm form there, verified correct against the per-pair
  reference), and every cross form of the paths fold collapsed 5 reachable
  pairs to 1. Older engines therefore keep the legacy per-pair path queries
  and get the per-owned arm form — correctness beats round-trips.
- Correctness of the per-request snapshot cache (the honest-cache contract):
  the estate only changes via (a) THIS port's own mutations — every one
  (load/mark_owned/add_edge/cut/drop/scratch_copy) explicitly invalidates;
  (b) queries issued through this port object by surrounding code — the
  traffic proxy invalidates on any query text carrying a Cypher write
  clause (CREATE/MERGE/DELETE/DETACH/SET/REMOVE) and on any raw
  execute_command (GRAPH.DELETE et al.); (c) a bounded staleness window
  (SEVER_FALKOR_SNAPSHOT_TTL_MS, default 2000) covering out-of-band reloads
  and OTHER processes' mutations. Reachability itself is NEVER cached — the
  arms always re-measure, so an interdiction by any operator is reflected
  in the headline metric on the very next call; only the small immutable
  sets (owned/jewels) and counts carry the documented sub-TTL window, and
  the 15s UI poll cadence always exceeds it.
- PATHS_BATCH_QUERY_TEMPLATE folds the per-jewel canonical shortest-path
  queries of paths_to_jewels into ONE statement per principal (same
  per-pair semantics, same sorted-jewel result order);
  EDGE_FREQ_BATCH_QUERY_TEMPLATE folds edge_frequency's owned x jewels
  query fan-out into ONE statement (the owned-set predicate the reachability
  arms already use — a live-verified falkordb 6.0.0 parser quirk makes the
  UNWIND form unusable there: UNWIND+MATCH loses the binding).
- scratch_copy pipelines GRAPH.DELETE + GRAPH.COPY + the first snapshot
  measurement of the fresh copy in ONE round-trip (copy+first-measure
  overlap — the server executes them in order; the plan's projection
  measurements then start from a warm snapshot on the same pooled client).
- Timeout discipline is UNCHANGED: socket timeouts bound hangs, not query
  time (30s/10s defaults, env-overridable); query timeouts stay at their
  documented values; no retry logic exists — a stalled engine fails into
  the console's 503 exactly as before.

Round-trip receipts (counts per endpoint, before/after, measured on the
ryzen self-hosted engine and the Cloud instance) live in
tests/test_perf_client_folds.py (the count is asserted there so a
regression fails the suite) and in the audit7 report.
"""
from __future__ import annotations

import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
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
#
# audit7/perf-client: the two arms are independent read queries, so on a real
# engine client they are issued CONCURRENTLY over the connection pool (one
# wall-clock instead of two) — the query TEXTS are unchanged and still
# byte-identical to the README forms; the DB-free wire-shape tests see the
# original sequential order (they run on injected stubs, where the fold is
# disabled by construction).
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

# audit7/perf-client correctness fix (live-prod): on engines older than
# _MODERN_FALKORDB_VER the ALL-OWNED arm above undercounts — measured on the
# managed Cloud 4.22.0 with two owned principals (one reaching, one not):
# the arm returned ZERO reachable ids while the per-pair existence probe
# (REACHABILITY_QUERY_TEMPLATE — both endpoints $param-bound in one MATCH,
# the one form that engine evaluates correctly) sees the reacher. The same
# arm shape with the principal $param-bound (one pair of queries per owned
# principal) IS evaluated correctly there (live-verified: mixed-reach and
# no-reach principals both classify exactly as the per-pair reference does).
# reachability() selects per-owned arms on those engines; the arm texts
# otherwise mirror the all-owned forms above exactly (same predicates, same
# hop-cap slot).
PER_OWNED_REACHABILITY_ARM_TEMPLATES: tuple[str, ...] = (
    (
        "MATCH (o {{objectid: $oid}}), (t:Group) "
        "WHERE t.objectid ENDS WITH '-512' OR t.objectid ENDS WITH '-519' "
        "WITH o, t, shortestPath((o)-{pattern}->(t)) AS p "
        "WHERE p IS NOT NULL "
        "RETURN DISTINCT o.objectid AS oid"
    ),
    (
        "MATCH (o {{objectid: $oid}}), (t:AZUser) "
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
# 100 paths). The canonical form is the WITH-clause expression — audit5
# cross-checked both engines (Cloud 4.22.0 + self-hosted 6.0.0): the WITH
# form AND the RETURN form both parse+run on each, but the WITH form is the
# one shipped everywhere. algo.SPpaths enumerates ties but yields raw node
# ids on edges — hence the index-zip hop parser below. The traversal set is
# passed server-side via `relTypes` (live-verified honored on BOTH engines:
# a CONTAINED_BY-only pair returns 0 rows under relTypes ['MEMBER_OF']) and
# re-enforced app-side, because SPpaths has NO working hop-bound config on
# falkordb 6.0.0 — unknown config keys such as `maxHops` are accepted and
# silently ignored (a 12-hop path is returned even under maxHops: 2), so the
# hop cap is applied to the parsed hops.
# audit5/cloud-instance correction: the "unhandled type in inlined
# properties" error was NOT an intermittent churn bug — it is the
# deterministic 6.0.0 parser's rejection of the raw {{…}}-escaped template
# that this module used to ship unformatted (4.22.0 rejects it with
# "Invalid input '{'"); the template is now .format()-ed before it reaches
# the engine, verified live on both. One more reason the live loop and the
# reachability metric use only the canonical shortestPath form anyway.
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

# Atomic delete-and-count: ONE engine-side statement removes the relationship
# and reports how many it removed. The previous count-then-delete pair was a
# TOCTOU seam under the console's multi-client traffic: two operators cutting
# the same edge concurrently could BOTH read the pre-count (n=1) before either
# DELETE ran, so both receipts claimed relationships_removed=1 for one edge —
# the ledger double-claimed a single removal (measured 6/6 race rounds,
# audit5/multi-client, cross-process). The engine executes each command
# atomically, so the single-statement form serializes: the first cutter
# removes and counts 1; the second matches zero rows and honestly returns
# 0 -> verdict no_effect. Live-verified on falkordb 6.0.0 (delete-return-count
# form returns [[1]] on a match and [[0]] on no match, including parallel-edge
# removals counted per matched row).
CUT_ATOMIC_QUERY_TEMPLATE = (
    "MATCH (s {{objectid: $src}})-[r:{rel}]->(t {{objectid: $dst}}) "
    "DELETE r RETURN count(r) AS n"
)

MARK_OWNED_QUERY = "MATCH (n {objectid: $oid}) SET n.owned = true"

# Principals that can hold (possibly legitimate) access flows — the pool the
# benign-usage/collateral estimate samples over (sever/core/scoring.py).
USER_OBJECTIDS_QUERY = "MATCH (u:User) RETURN u.objectid AS objectid ORDER BY objectid"

# ---------------------------------------------------------------------------
# audit7/perf-client: the round-trip folds. Every fold below is semantically
# the CONCATENATION of the documented single-purpose queries above — same
# predicates, same labels, same aggregates — issued as ONE statement so the
# engine round-trip is paid once instead of 4-6 times. Equivalence against
# the legacy per-query forms is pinned on the real engine by
# tests/test_perf_client_folds.py; an engine that rejects a fold (response
# error) gets the legacy forms forever after (per-port capability flag).
# ---------------------------------------------------------------------------

# node_count + edge_count + owned_ids + JEWELS_QUERY + AZ_JEWELS_QUERY in one
# statement. The OPTIONAL MATCHes keep the single aggregate row alive on every
# empty case (no owned principals / no -512|-519 Groups / no GA holders / no
# edges / an entirely empty graph), so one row always comes back with the
# exact values the five separate queries would have returned (collect() over
# no rows is []; count() over no rows is 0).
ESTATE_SNAPSHOT_QUERY = (
    "MATCH (n {owned: true}) WITH collect(n.objectid) AS owned "
    "OPTIONAL MATCH (g:Group) "
    "WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' "
    "WITH owned, collect(g.objectid) AS ad_jewels "
    "OPTIONAL MATCH (u:AZUser) "
    "WHERE toLower(u.name) ENDS WITH '-globaladministrator' "
    "WITH owned, ad_jewels, collect(u.objectid) AS az_jewels "
    "OPTIONAL MATCH (n) WITH owned, ad_jewels, az_jewels, count(n) AS nodes "
    "OPTIONAL MATCH ()-[r]->() "
    "RETURN owned, ad_jewels, az_jewels, nodes, count(r) AS edges"
)

# paths_to_jewels fold: ONE statement enumerates the canonical shortest path
# from one principal to EVERY crown jewel (the per-(principal, jewel) pairs
# the legacy loop issued one CANONICAL_PATH_QUERY_TEMPLATE per jewel for).
# The jewel predicate is exactly JEWELS_QUERY's OR AZ_JEWELS_QUERY's; the
# shortestPath form is exactly the canonical one. Rows come back keyed by
# target so results are re-ordered app-side into the legacy sorted-jewel
# order — the returned list is identical, not merely equal as a set.
PATHS_BATCH_QUERY_TEMPLATE = (
    "MATCH (o {{objectid: $oid}}) "
    "MATCH (t) WHERE (t:Group AND (t.objectid ENDS WITH '-512' "
    "OR t.objectid ENDS WITH '-519')) "
    "OR (t:AZUser AND toLower(t.name) ENDS WITH '-globaladministrator') "
    "WITH o, t, shortestPath((o)-{pattern}->(t)) AS p "
    "WHERE p IS NOT NULL "
    "RETURN p, t.objectid AS target"
)

# edge_frequency fold: ONE statement enumerates the canonical shortest paths
# from EVERY owned principal to EVERY crown jewel — the same owned-set
# predicate (``{owned: true}``) the reachability arms use, the same jewel
# predicate, the same canonical shortestPath form. It replaces the legacy
# owned x jewels query fan-out (one paths_to_jewels call per owned, one
# canonical query per jewel inside each). Frequency is still counted
# app-side over the parsed hops, in the legacy owned-sorted x jewel-sorted
# order, so the dict is insertion-order identical too.
#
# Live-verified engine quirk (falkordb 6.0.0, ryzen): UNWIND is NOT a viable
# batch form here — every UNWIND-then-MATCH variant fails with
# "'<var>' not defined" (the parser loses the UNWIND binding before a MATCH
# clause; UNWIND+RETURN and UNWIND+MERGE are fine, UNWIND+MATCH is not).
# The owned-set predicate achieves the same single-statement batch with no
# bound variable, and mirrors REACHABILITY_ARM_TEMPLATES exactly.
EDGE_FREQ_BATCH_QUERY_TEMPLATE = (
    "MATCH (o {{owned: true}}) "
    "MATCH (t) WHERE (t:Group AND (t.objectid ENDS WITH '-512' "
    "OR t.objectid ENDS WITH '-519')) "
    "OR (t:AZUser AND toLower(t.name) ENDS WITH '-globaladministrator') "
    "WITH o, t, shortestPath((o)-{pattern}->(t)) AS p "
    "WHERE p IS NOT NULL "
    "RETURN o.objectid AS src, t.objectid AS target, p"
)

# Any query whose TEXT carries a Cypher write clause mutates the estate, so
# the snapshot cache is dropped before the next read sees it. Conservative by
# construction: a false positive only costs a refetch, never a stale answer.
# (Port-internal mutations invalidate explicitly as well; this guard is for
# queries issued through ``port.graph`` by surrounding code and tests.)
_WRITE_CLAUSE_RE = re.compile(r"\b(create|merge|detach|delete|set|remove)\b", re.IGNORECASE)

# Shared executor for the independent reachability arms (and nothing else —
# mutations stay sequential). Bounded so a poll storm can only queue, never
# spawn unbounded threads; idle threads are joined at interpreter exit by
# concurrent.futures' own atexit hook.
_ARM_POOL: ThreadPoolExecutor | None = None
_ARM_POOL_MAX = 8

# The engine family where the cross-product shortestPath forms below were
# live-verified equivalent (falkordb 6.0.0, module 'graph' ver 60000 — the
# self-hosted/Docker engine). The managed FalkorDB Cloud instance reports
# 42200 (4.22.0) and its planner computes WITH-clause shortestPath for only
# ONE row of a multi-row (o x t) binding — live-verified: the all-owned
# reachability arm over 2 owned principals (one of which reaches) returned
# ZERO rows where the per-pair probe sees one, and every cross-form of the
# paths fold collapsed 5 reachable pairs to 1. On engines below this
# version the port therefore uses the per-owned arm form (correct there,
# live-verified) and keeps paths/edge-frequency on the legacy per-pair
# queries — correctness beats round-trips, and the per-port engine version
# is probed once (MODULE LIST) so the choice is deterministic per engine.
_MODERN_FALKORDB_VER = 60000


def _arm_pool() -> ThreadPoolExecutor:
    global _ARM_POOL
    if _ARM_POOL is None:
        _ARM_POOL = ThreadPoolExecutor(
            max_workers=_ARM_POOL_MAX, thread_name_prefix="sever-arm"
        )
    return _ARM_POOL


def _is_engine_form_error(exc: BaseException) -> bool:
    """True only when the ENGINE REJECTED THE QUERY FORM (a response error),
    never for a timeout/connection problem — a slow-but-working engine must
    never silently downgrade the port to more round-trips."""
    try:
        from redis.exceptions import ResponseError

        return isinstance(exc, ResponseError)
    except ImportError:  # pragma: no cover — falkordb always ships redis-py
        return False


class _CountingClient:
    """Passthrough for the raw redis client that keeps the round-trip audit
    honest for non-GRAPH.QUERY commands (GRAPH.DELETE/GRAPH.COPY/PROFILE …)
    and drops the snapshot cache conservatively: a raw command may be any
    mutation, and an out-of-band GRAPH.DELETE (conftest's drop_graph, an
    operator's reset) must never be served from cache."""

    __slots__ = ("_inner", "_port")

    def __init__(self, inner: Any, port: "FalkorGraphPort") -> None:
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_port", port)

    def execute_command(self, *args: Any, **kwargs: Any) -> Any:
        port = self._port
        port._command_count += 1
        port._note_rt(str(args[0]) if args else "?", "")
        port._invalidate()
        return self._inner.execute_command(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _CountingGraph:
    """Passthrough for the falkordb graph object that (a) counts every
    GRAPH.QUERY for the round-trip audit, (b) drops the snapshot cache when a
    query text carries a write clause. Attribute access (``.calls`` on test
    stubs, ``.client``, ``._build_params_header`` …) delegates untouched, so
    every existing wire-shape contract against injected clients keeps
    working verbatim."""

    __slots__ = ("_inner", "_port", "_client_proxy")

    def __init__(self, inner: Any, port: "FalkorGraphPort") -> None:
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_port", port)
        object.__setattr__(self, "_client_proxy", None)

    def query(self, *args: Any, **kwargs: Any) -> Any:
        port = self._port
        port._query_count += 1
        text = str(args[0]) if args else ""
        port._note_rt("GRAPH.QUERY", text)
        if _WRITE_CLAUSE_RE.search(text):
            port._invalidate()
        return self._inner.query(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        if name == "client":
            client = getattr(self._inner, "client")  # AttributeError on stubs
            cached = self._client_proxy
            if cached is None or cached._inner is not client:
                cached = _CountingClient(client, self._port)
                object.__setattr__(self, "_client_proxy", cached)
            return cached
        return getattr(self._inner, name)


class FalkorGraphPort(GraphPort):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        graph_name: str = "sever_demo",
        username: str | None = None,
        password: str | None = None,
        client: Any | None = None,
    ) -> None:
        # audit7 instrumentation state first — the traffic proxy needs it.
        self._query_count = 0
        self._command_count = 0
        self._rt_log: list[str] = []
        self._snapshot: dict[str, Any] | None = None
        self._snapshot_at = 0.0
        self._fold_supported = True
        self._pipeline_supported = True
        self._engine_graph_ver: int | None = None  # probed once, inherited by copies
        # Bounded staleness window for the snapshot cache (see module header
        # for the honesty contract). 0 disables the folds entirely — the port
        # then issues exactly the legacy per-query sequence.
        self._snapshot_ttl = (
            float(os.environ.get("SEVER_FALKOR_SNAPSHOT_TTL_MS", "2000")) / 1000.0
        )
        if client is not None:
            graph = client
        else:
            from falkordb import FalkorDB

            # socket timeouts bound HANGS, not query time: without them redis-py
            # waits forever on a stalled remote engine (the live Render->Cloud
            # deployment hit a multi-second latency window where requests
            # dragged until the proxy cut them, surfacing as empty responses).
            # A stalled query now fails in <= SEVER_FALKOR_SOCKET_TIMEOUT
            # seconds as a clean ConnectionError -> the console's 503 JSON.
            #
            # TCP keepalive (audit5/latency-forensics) keeps the pooled
            # engine connection provably alive across the 10-minute
            # keep-alive ping gap so a middlebox idle timeout (AWS NLB
            # defaults to 350s) can never silently strand it: measured, a
            # FalkorDB Cloud connection survives >=620s idle untouched
            # (server tcp-keepalive 300 helps), and redis-py applies
            # SO_KEEPALIVE + these options at connect time (verified against
            # falkordb-py 6.x: FalkorDB.__init__ passes both straight into
            # redis.Redis -> Connection). Options tuned so a dead peer is
            # detected in ~60s (< the 30s socket timeout's worst case is
            # unchanged; the OS probes instead of the request hanging on a
            # socket nobody is answering). Linux (Render) accepts all three;
            # Windows has no TCP_KEEPIDLE -> plain SO_KEEPALIVE there.
            keepalive_options = {}
            if hasattr(socket, "TCP_KEEPIDLE"):
                keepalive_options = {
                    socket.TCP_KEEPIDLE: 30,
                    socket.TCP_KEEPINTVL: 10,
                    socket.TCP_KEEPCNT: 3,
                }
            fdb = FalkorDB(
                host=host, port=port, username=username, password=password,
                socket_timeout=int(os.environ.get("SEVER_FALKOR_SOCKET_TIMEOUT", "30")),
                socket_connect_timeout=int(os.environ.get("SEVER_FALKOR_CONNECT_TIMEOUT", "10")),
                socket_keepalive=True,
                socket_keepalive_options=(keepalive_options or None),
            )
            graph = fdb.select_graph(graph_name)
        self._raw_graph = graph
        # The engine traffic proxy: counts queries, invalidates the snapshot
        # cache on observed writes. Everything else delegates verbatim, so
        # ``port.graph`` keeps every attribute the wire-shape tests and
        # app.py use directly (query, client, _build_params_header, stub
        # ``calls`` ledgers …).
        self.graph = _CountingGraph(graph, self)
        self.graph_name = graph_name

    INDEXED_LABELS = (
        "User", "Group", "Computer", "Domain", "OU", "GPO", "Container",
        "CertTemplate", "EnterpriseCA", "RootCA", "AIACA", "NTAuthStore",
        "AZUser", "AZServicePrincipal", "AZApp",
    )

    # ---- audit7/perf-client: fold machinery + round-trip audit --------------

    def _probe_engine_version(self) -> int:
        """falkordb 'graph' module version (e.g. 60000 = 6.0.0, 42200 = 4.22.0),
        probed lazily ONCE per port via MODULE LIST and inherited by scratch
        copies (so a plan's copy never re-pays the probe). The probe RT is
        absorbed by the first accessor burst of a port's life (console boot,
        the receipts driver's warmup pass) — it never lands inside a measured
        endpoint sequence.
        0 = probe failed -> conservative: the engine is treated as NOT
        supporting the cross-product fold forms (the legacy per-query forms
        always tell the truth; a wrong fast answer is never acceptable)."""
        if self._engine_graph_ver is not None:
            return self._engine_graph_ver
        ver = 0
        try:
            mods = self._raw_graph.client.execute_command("MODULE", "LIST")
            for entry in mods:
                items = entry if isinstance(entry, (list, tuple)) else [entry]
                pairs = [(str(items[i]), items[i + 1])
                         for i in range(0, len(items) - 1, 2)]
                if ("name", "graph") in pairs:
                    for key, value in pairs:
                        if key == "ver":
                            ver = int(value)
        except Exception:
            ver = 0
        self._engine_graph_ver = ver
        return ver

    @property
    def _modern_engine(self) -> bool:
        """True only on the engine family where every cross-product fold form
        was live-verified equivalent (>= _MODERN_FALKORDB_VER, falkordb 6.x)."""
        return self._probe_engine_version() >= _MODERN_FALKORDB_VER

    @property
    def _fold_active(self) -> bool:
        """Folds run only on a REAL falkordb client with caching enabled and
        the engine accepting the combined forms. Injected stubs (the DB-free
        wire-shape tests) keep the exact legacy call sequence."""
        return (
            self._fold_supported
            and self._snapshot_ttl > 0.0
            and hasattr(self._raw_graph, "client")
        )

    def _invalidate(self) -> None:
        """Drop the cached estate snapshot — the honest-cache contract's
        explicit-invalidation arm (see module header)."""
        self._snapshot = None

    def _note_rt(self, kind: str, head: str) -> None:
        if len(self._rt_log) < 512:
            self._rt_log.append(f"{kind} {head[:96]}")

    def rt_reset(self) -> None:
        """Zero the round-trip counters (audit driver seam)."""
        self._query_count = 0
        self._command_count = 0
        self._rt_log.clear()

    def rt_receipt(self) -> dict[str, Any]:
        """Round-trip audit receipt: GRAPH.QUERY count, raw-command count,
        their sum, and the queries seen (heads only — no params ever)."""
        return {
            "query_count": self._query_count,
            "command_count": self._command_count,
            "roundtrips": self._query_count + self._command_count,
            "queries": list(self._rt_log),
        }

    def _snapshot_fresh(self) -> dict[str, Any] | None:
        snap = self._snapshot
        if snap is None:
            return None
        if (time.monotonic() - self._snapshot_at) > self._snapshot_ttl:
            self._snapshot = None
            return None
        return snap

    @staticmethod
    def _parse_snapshot_row(row: Any) -> dict[str, Any] | None:
        if row is None or len(row) != 5:
            return None
        return {
            "owned": [str(x) for x in row[0]],
            "ad_jewels": [str(x) for x in row[1]],
            "az_jewels": [str(x) for x in row[2]],
            "nodes": int(row[3]),
            "edges": int(row[4]),
        }

    def _estate_snapshot(self) -> dict[str, Any] | None:
        """Owned + jewels + counts, as ONE engine statement, cached within the
        request burst (TTL-bounded). Returns None whenever the fold is off or
        the engine did not answer the combined form — callers then use the
        legacy queries, which always tell the truth."""
        snap = self._snapshot_fresh()
        if snap is not None:
            return snap
        if not self._fold_active:
            return None
        try:
            res = self.graph.query(ESTATE_SNAPSHOT_QUERY, timeout=60000)
        except Exception as exc:
            if _is_engine_form_error(exc):
                self._fold_supported = False
            raise
        rows = res.result_set
        if not rows:
            # No row where the aggregate chain must always produce one: do
            # NOT trust the fold for this read (and do not disable it either —
            # the empty-graph case is retried on the next call; the legacy
            # accessors answer this read truthfully).
            return None
        parsed = self._parse_snapshot_row(rows[0])
        if parsed is None:
            return None
        self._snapshot = parsed
        self._snapshot_at = time.monotonic()
        return parsed

    def _seed_snapshot(self, raw_response: Any) -> bool:
        """Adopt a snapshot measured by a pipelined command (scratch_copy's
        copy+first-measure overlap) — parsed with falkordb's own QueryResult.
        Any parse problem just leaves the cache cold: the first accessor
        re-measures honestly."""
        try:
            from falkordb import QueryResult

            rows = QueryResult(self._raw_graph, raw_response).result_set
            if not rows:
                return False
            parsed = self._parse_snapshot_row(rows[0])
            if parsed is None:
                return False
            self._snapshot = parsed
            self._snapshot_at = time.monotonic()
            return True
        except Exception:
            return False

    # ---- load ----
    def load(self, graph: NormalizedGraph) -> None:
        self._invalidate()  # a load replaces the estate: no cached value survives
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
        self._invalidate()  # index creation is a write too — drop any pre-load cache

    def _scalar(self, query: str, params: dict[str, Any] | None = None, timeout_ms: int = 60000) -> Any:
        res = self.graph.query(query, params or {}, timeout=timeout_ms)
        return res.result_set[0][0] if res.result_set else None

    def node_count(self) -> int:
        if self._fold_active:
            snap = self._estate_snapshot()
            if snap is not None:
                return snap["nodes"]
        return int(self._scalar("MATCH (n) RETURN count(n)"))

    def edge_count(self) -> int:
        if self._fold_active:
            snap = self._estate_snapshot()
            if snap is not None:
                return snap["edges"]
        return int(self._scalar("MATCH ()-[r]->() RETURN count(r)"))

    # ---- owned / jewels ----
    def mark_owned(self, objectid: str) -> None:
        self.graph.query(MARK_OWNED_QUERY, {"oid": objectid})
        self._invalidate()  # owned set changed: cached owned lists are stale

    def owned_ids(self) -> list[str]:
        if self._fold_active:
            snap = self._estate_snapshot()
            if snap is not None:
                return sorted(snap["owned"])
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
    #
    # audit7/perf-client: on a real client the delete+copy AND the first
    # measurement of the fresh copy travel in ONE redis pipeline — one WAN
    # round-trip for the whole copy step — and the copy's snapshot lands
    # pre-warmed in the new port, so the plan's first projection starts
    # measuring immediately. The scratch graph uses the SAME underlying
    # connection pool (one client, one pool — no new connections per copy).
    def scratch_copy(self, scratch_name: str) -> "FalkorGraphPort":
        """Return a port on a fresh isolated copy of THIS graph.

        Idempotent like every other graph lifecycle path: an existing
        destination key is deleted first, mirroring make_live_port's
        hermetic-start rule (a leftover scratch from a crashed run must
        never be silently re-used and serve stale state into a plan).
        """
        from falkordb import Graph as _Graph

        # The FalkorDB wrapper exposes execute_command but keeps the pooled
        # redis.Redis at ``.connection`` — the pipeline lives there. Same
        # connection pool as every other query (no new connections per copy).
        # transaction=False: the commands are buffered and issued over ONE
        # round-trip WITHOUT MULTI/EXEC wrapping — the managed Cloud engine
        # (4.22.0) rejects module commands inside a transaction ("Blocking
        # module command called from transaction"), live-verified; the
        # self-hosted 6.0.0 engine accepts both forms.
        falkor_client = self._raw_graph.client
        redis_client = getattr(falkor_client, "connection", None)
        if (
            self._fold_active
            and self._pipeline_supported
            and redis_client is not None
            and hasattr(redis_client, "pipeline")
        ):
            try:
                pipe = redis_client.pipeline(transaction=False)
                pipe.execute_command("GRAPH.DELETE", scratch_name)  # may miss: fine
                pipe.execute_command("GRAPH.COPY", self.graph_name, scratch_name)
                pipe.execute_command(
                    "GRAPH.QUERY", scratch_name, ESTATE_SNAPSHOT_QUERY,
                    "--compact", "timeout", 60000,
                )
                self._command_count += 1  # ONE round-trip, three commands
                self._note_rt("GRAPH.PIPELINE(delete+copy+snapshot)", scratch_name)
                self._invalidate()
                res = pipe.execute(raise_on_error=False)
                copy_res = res[1] if len(res) > 1 else None
                if isinstance(copy_res, Exception):
                    raise copy_res  # the copy failed for a real reason — never mask it
                new_port = FalkorGraphPort(
                    client=_Graph(client=falkor_client, name=scratch_name),
                    graph_name=scratch_name,
                )
                snap_res = res[2] if len(res) > 2 else None
                if not isinstance(snap_res, Exception) and snap_res is not None:
                    new_port._seed_snapshot(snap_res)
                new_port._engine_graph_ver = self._engine_graph_ver  # inherit the probe
                return new_port
            except Exception as exc:
                if not _is_engine_form_error(exc):
                    raise
                # the ENGINE rejects the pipelined form itself (not a copy
                # failure): permanent, honest downgrade — the legacy
                # delete/copy commands below are always correct
                self._pipeline_supported = False
        try:
            self.graph.client.execute_command("GRAPH.DELETE", scratch_name)
        except Exception:
            pass  # no such key — the normal case
        self.graph.client.execute_command("GRAPH.COPY", self.graph_name, scratch_name)
        new_port = FalkorGraphPort(
            client=_Graph(client=falkor_client, name=scratch_name),
            graph_name=scratch_name,
        )
        new_port._engine_graph_ver = self._engine_graph_ver  # inherit the probe
        return new_port

    def drop(self) -> None:
        """Delete this port's graph key idempotently. Terminal for the port —
        the plan projection's scratch graphs are dropped in a ``finally`` so
        a crashed plan can never leak a scratch estate on the engine."""
        self._invalidate()  # the estate is gone: nothing may be served from cache
        try:
            self.graph.client.execute_command("GRAPH.DELETE", self.graph_name)
        except Exception:
            pass

    def crown_jewels(self) -> list[str]:
        if self._fold_active:
            snap = self._estate_snapshot()
            if snap is not None:
                # exactly the legacy merge: AD jewels + AZ jewels, sorted
                return sorted(snap["ad_jewels"] + snap["az_jewels"])
        jewels = [str(row[0]) for row in self.graph.query(JEWELS_QUERY).result_set]
        jewels += [str(row[0]) for row in self.graph.query(AZ_JEWELS_QUERY).result_set]
        return sorted(jewels)

    # ---- traversal core ----
    def _arm_reached_ids(self, query: str, params: dict[str, Any] | None = None) -> list[str]:
        if params is None:
            res = self.graph.query(query, timeout=60000)
        else:
            res = self.graph.query(query, params, timeout=60000)
        return [str(row[0]) for row in res.result_set]

    def _reachability_legacy(self, hop_cap: int) -> int:
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

    def reachability(self, hop_cap: int = DEFAULT_HOP_CAP) -> int:
        if not self._fold_active:
            return self._reachability_legacy(hop_cap)
        # The arms are INDEPENDENT read queries — issue them concurrently over
        # the connection pool (one wall-clock instead of many) and overlap the
        # snapshot fetch with them. The arms are NEVER cached, so an
        # interdiction by ANY operator is visible in the headline metric on
        # the very next call. The first arm exception propagates as-is — no
        # retry, no masking.
        pattern = cypher_traversal_pattern(hop_cap)
        pool = _arm_pool()
        futures: list[Any] = []
        if self._modern_engine:
            # falkordb 6.x (verified): the all-owned two-arm form — 2 queries
            # for any number of owned principals.
            futures = [
                pool.submit(self._arm_reached_ids, arm.format(pattern=pattern))
                for arm in REACHABILITY_ARM_TEMPLATES
            ]
            snap = self._estate_snapshot()  # overlaps the arms in flight
        else:
            # Older engines (live-verified on the managed Cloud 4.22.0)
            # evaluate the cross-product arm for a single row and UNDERCOUNT
            # with 2+ owned principals (measured: 2 owned -> 0 reachable where
            # the per-pair probe sees 1) — the same arm with the principal
            # $param-bound is evaluated correctly there. Correctness beats
            # round-trips: 2 queries per owned principal.
            snap = self._estate_snapshot()
            owned = snap["owned"] if snap is not None else self.owned_ids()
            futures = [
                pool.submit(
                    self._arm_reached_ids,
                    arm.format(pattern=pattern),
                    {"oid": principal},
                )
                for principal in owned
                for arm in PER_OWNED_REACHABILITY_ARM_TEMPLATES
            ]
        reached: set[str] = set()
        for fut in futures:
            reached.update(fut.result())
        if snap is not None:
            jewel_set = set(snap["ad_jewels"]) | set(snap["az_jewels"])
            reached.update(o for o in snap["owned"] if o in jewel_set)
        else:
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

        audit7/perf-client: on a live client the canonical per-jewel queries
        fold into ONE statement (PATHS_BATCH_QUERY_TEMPLATE) — same per-pair
        semantics, and rows are re-ordered app-side into the legacy
        sorted-jewel order so the returned list is identical, not merely
        equal. An engine that rejects the fold keeps the per-jewel loop.
        """
        pattern = cypher_traversal_pattern(hop_cap)
        paths: list[list[tuple[str, str, str]]] = []
        if not ties and self._fold_active and self._modern_engine:
            # (cross-product shortestPath forms are falkordb-6.x-verified;
            # older engines keep the legacy per-jewel loop below — correct
            # there, live-verified against the per-pair probe)
            jewels = self.crown_jewels()  # snapshot-served — 0 round-trips warm
            if jewels:
                try:
                    res = self.graph.query(
                        PATHS_BATCH_QUERY_TEMPLATE.format(pattern=pattern),
                        {"oid": objectid},
                        timeout=30000,
                    )
                except Exception as exc:
                    if not _is_engine_form_error(exc):
                        raise
                    self._fold_supported = False
                else:
                    by_target: dict[str, list[tuple[str, str, str]]] = {}
                    for row in res.result_set:
                        hops = _row_to_hops(row)  # row[0] is the path
                        if hops:
                            by_target[str(row[1])] = hops
                    # legacy order: one path per jewel, jewels sorted — the
                    # exact sequence the per-jewel loop produced
                    for jewel in jewels:
                        hops = by_target.get(jewel)
                        if not hops:
                            continue
                        if len(hops) > hop_cap or any(
                            rel not in TRAVERSAL_RELS_SET for _, rel, _ in hops
                        ):
                            continue
                        paths.append(hops)
                    return paths
        for jewel in self.crown_jewels():
            query = (
                # .format() unwraps the {{...}} escapes into the literal Cypher
                # the engine parses — until audit5/cloud-instance the RAW
                # template reached the engine and was rejected on BOTH engines
                # (4.22.0: "Invalid input '{'"; 6.0.0: "unhandled type in
                # inlined properties") — the ties mode was dead at the engine,
                # masked by test_live_semantics' broad engine-bug except.
                PATH_QUERY_TEMPLATE.format()
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
        if self._fold_active and self._modern_engine:
            # (the owned-set batch is a cross-product shortestPath form —
            # falkordb-6.x-verified; older engines fall through to the legacy
            # loop, which is correct there)
            owned = self.owned_ids()      # snapshot-served — 0 round-trips warm
            jewels = self.crown_jewels()  # snapshot-served — 0 round-trips warm
            if owned and jewels:
                try:
                    res = self.graph.query(
                        EDGE_FREQ_BATCH_QUERY_TEMPLATE.format(
                            pattern=cypher_traversal_pattern(hop_cap)
                        ),
                        timeout=60000,
                    )
                except Exception as exc:
                    if not _is_engine_form_error(exc):
                        raise
                    self._fold_supported = False
                else:
                    by_pair: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
                    for row in res.result_set:
                        hops = _row_to_hops((row[2],))  # row: (src, target, path)
                        if hops:
                            by_pair[(str(row[0]), str(row[1]))] = hops
                    freq: dict[tuple[str, str, str], int] = {}
                    # legacy iteration order (owned sorted x jewels sorted):
                    # insertion-order-identical dict, replay-identical receipts
                    for src in owned:
                        for jewel in jewels:
                            hops = by_pair.get((src, jewel))
                            if not hops:
                                continue
                            if len(hops) > hop_cap or any(
                                rel not in TRAVERSAL_RELS_SET for _, rel, _ in hops
                            ):
                                continue
                            for hop in hops:
                                freq[hop] = freq.get(hop, 0) + 1
                    return freq
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
        self._invalidate()  # the estate may have changed: no cached set survives
        return pre is not None and int(pre) == 0

    def cut(self, src: str, dst: str, rel: str) -> int:
        if not _valid_rel(rel):
            raise ValueError(f"invalid relationship type: {rel!r}")
        # Single atomic statement: the count is computed by the engine over the
        # same MATCH that performs the DELETE, so no concurrent cutter can read
        # a stale pre-count (see CUT_ATOMIC_QUERY_TEMPLATE). ``count(r)`` still
        # returns a row on zero matches, so ``_scalar`` never sees None here.
        query = CUT_ATOMIC_QUERY_TEMPLATE.format(rel=rel)
        removed = int(self._scalar(query, {"src": src, "dst": dst}))
        self._invalidate()  # the estate changed: counts/frequencies are stale
        return removed

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
