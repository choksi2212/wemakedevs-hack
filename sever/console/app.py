"""SEVER console — the agent's cockpit. FastAPI over the live FalkorDB engine.

The human gate is a real HTTP round-trip: the UI renders the ranked proposal
and the operator clicks APPROVE — the cut executes only on that explicit call.

Run:
    uvicorn sever.console.app:app --host 0.0.0.0 --port 8000
Env: SEVER_FALKOR_HOST/PORT/USER/PASSWORD, SEVER_FALKOR_GRAPH,
     SEVER_SAMPLE_DIR — a .env at the repo root is loaded automatically
     (real environment always wins).

API contract (audit2/api-contract), enforced by sever.console.schemas BEFORE
any handler runs:
- 422 schema: malformed JSON, wrong types, missing fields, empty required
  strings, oversized fields (100KB subject dies here), rel syntax violations
  (injection payloads, trailing newlines, >64 chars), truthy non-bool
  ``approved`` (1, 1.0, "true", "yes", "on", "1"), lone surrogates,
  unknown finding ``kind`` (closed ATT&CK vocabulary) and ``ace_granted``
  findings without a real target/rel grant (audit3/console-logic).
- 400 vocabulary/estate: a syntactically valid but unknown rel (e.g. "generic_all")
  reaches FalkorGraphPort's closed-vocabulary guard and is a client error,
  never a 500. A finding whose subject/target does not resolve to a
  principal of the loaded estate is likewise a client error — pre-fix it was
  a 200 phantom no-op narrated as "this principal is now assumed controlled"
  (audit3/console-logic, live-verified).
- 403 gate: the cut handler accepts only ``approved is True`` — the schema's
  StrictBool guarantees nothing else can ever be True here.
- 503 engine outage: FalkorDB connection failures surface as a clean JSON
  503 — never a bare 500 with an unparseable body (which left the UI banner
  rendering a JSON-parse artifact instead of the cause). A finding/cut that
  was mid-flight when the engine died is recorded on the receipts ledger as
  ``finding_failed``/``cut_failed`` with ``outcome: unknown`` — the trail
  never invents a success and never loses the attempt.

audit7/perf-api — the fold layer (equivalence-pinned, engine-call receipts):
The console used to re-ask the engine everything it already knew. Measured
against the local engine (receipts: 2026-10-16, ryzen, sample estate, HERO
owned): GET /api/state cost 11 sequential round-trips per poll (two owned
scans, crown jewels twice — once alone, once inside reachability — plus
reachability's own internal re-reads), GET /api/proposal 185, GET /api/plan
398 — on the Cloud's ~35ms RTT that is the 13s+ /api/plan block. The fold:

- ONE "estate probe" query returns nodes, edges, owned and BOTH jewel arms in
  a single round-trip. It is ASSEMBLED from FalkorGraphPort's own module
  constants (JEWELS_QUERY/AZ_JEWELS_QUERY/OWNED_QUERY prefixes), so a port
  whose semantics change makes the fold refuse itself (``_FoldUnsupported``)
  and the handler falls back to the exact original port-method path — the
  fold can serve an answer the slow path would not, or it falls back.
- the reachability/paths/benign enumeration is batched: the same two
  REACHABILITY_ARM_TEMPLATES the port ships, with the DISTINCT collapsed
  RETURN widened to ``o, t, p`` — one shortestPath per (principal, jewel)
  pair, the identical per-pair semantics paths_to_jewels uses (live-verified
  hop-identical: 5/5 owned paths and 31/31 benign rows, zero mismatches).
- /api/state answers from cache when nothing changed: every mutation
  endpoint bumps a generation counter (cut / plan-execute / finding,
  including the outcome-unknown outage lanes), and the probe row itself is
  the estate generation — (nodes, edges, owned, jewels). A cache hit costs
  ONE engine call (the probe) and re-serves the last full computation; any
  console mutation, any out-of-band cut/add/own/jewel change visible in the
  probe, forces a full re-measure. Honest boundary: an out-of-band rewrite
  that simultaneously preserves node count, edge count, the owned set AND
  the jewel set between two polls is the one thing the generation check
  cannot see; no console mutation can be silent (all bump the counter).
  Receipt: cold poll 4 engine calls (probe + 2 arms + first-time name
  lookups), warm poll 1, post-mutation poll 3 — from 11/11/11.
- /api/plan runs the SAME greedy k=3 copy+measure algorithm as
  scoring.plan_cut_sequence (same scratch GRAPH.COPY isolation, same
  per-step re-measure, same verdict rules, byte-identical receipt fields),
  but the per-step enumeration is the two batched arms and the benign
  sample is measured once for the pool that cannot change on a scratch the
  plan only cuts edges on. Receipt: 398 -> ~21 round-trips; wall time is the
  two per-step traversals, not round-trip count.
- fallback parity: engine-free fake ports (resilience suite) never speak the
  folded dialect — the probe returns None and every handler answers through
  the original port-method path, so the resilience contracts (503 lanes,
  honest ledgers) are exercised on the same code they pinned.
- F900 (production, audit8/fix-code): the reach/paths/benign/projection arm
  folds above are the port's cross-product WITH-shortestPath forms, so they
  inherit the port's engine-version probe via ``_arms_ok`` — on engines
  < falkordb 6.0.0 (the managed Cloud 4.22.0 the deployment runs on) those
  forms undercount or return nothing, and production served reach 0 / paths
  [] with an owned principal while the plan endpoint's per-pair path was
  still correct. Old engines (and any port without the probe attribute —
  every engine-free fake) answer through the original port-method path,
  exactly as production did pre-fleet-7; modern engines keep the folds,
  byte-identical, equivalence-pinned.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import Response
from dotenv import load_dotenv

from sever.agent.investigator import Investigator
from sever.console.schemas import CutRequest, FindingRequest, PlanExecuteRequest
from sever.console.security import SECURITY_HEADERS, BodySizeLimitMiddleware
from sever.core.falkor_port import (
    AZ_JEWELS_QUERY,
    FalkorGraphPort,
    JEWELS_QUERY,
    OWNED_QUERY,
    REACHABILITY_ARM_TEMPLATES,
    _row_to_hops,
)
from sever.core.jewels import (
    DEFAULT_HOP_CAP,
    TRAVERSAL_RELS_SET,
    cypher_traversal_pattern,
)
from sever.core.port import GraphPort
from sever.core.scoring import BENIGN_SAMPLE_SIZE, rank_cut_candidates
from sever.etl.ad_collectors import parse_ad_dir
from sever.findings.attack_map import narrate
from sever.findings.stream import Finding
from sever.memory.flow import CaseLog


def _engine_outage_errors() -> tuple[type[BaseException], ...]:
    """The exception types a dead/unreachable FalkorDB raises (redis-py,
    which falkordb wraps). The console maps these to a clean 503."""
    try:
        from redis.exceptions import ConnectionError, TimeoutError

        return (ConnectionError, TimeoutError)
    except ImportError:  # pragma: no cover — falkordb always ships redis-py
        return (ConnectionError,)


ENGINE_ERRORS = _engine_outage_errors()


def _boot_probe_errors() -> tuple[type[BaseException], ...]:
    """The BOOT-time failure family: the outage classes plus the
    ``ResponseError`` a reachable-but-not-FalkorDB RESP server answers to
    GRAPH.QUERY with (verified live: Memurai on 6379 — INFO answers so the
    falkordb constructor succeeds, then the first graph query rejects). At
    boot these all mean "this endpoint cannot serve the product"; at REQUEST
    time the family deliberately stays the documented outage pair only —
    a ResponseError mid-request can be a genuine query bug and must fail
    loud, never masquerade as an outage."""
    try:
        from redis.exceptions import ResponseError

        return (*ENGINE_ERRORS, ResponseError)
    except ImportError:  # pragma: no cover — falkordb always ships redis-py
        return ENGINE_ERRORS


BOOT_PROBE_ERRORS = _boot_probe_errors()


class _UnreachablePort(GraphPort):
    """Stand-in port for a boot that found no engine (audit8/fix-code, F303):
    the falkordb client constructor itself dies when nothing listens (its
    eager ``Is_Sentinel`` INFO probe raises), so no port object exists at
    all. This shim re-raises the captured outage from every engine touch —
    every request then surfaces the registered 503 JSON lane exactly as a
    post-boot outage does. It never fabricates a single number; there is
    deliberately no ``graph`` attribute, so the folded fast paths detect a
    non-speaking port and fall to the port methods, which raise."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.graph_name = os.environ.get("SEVER_FALKOR_GRAPH", "sever_demo")

    def _raise(self) -> None:
        raise self._exc

    # ---- GraphPort protocol: every engine touch is the captured outage ----
    def load(self, graph: Any) -> None:
        self._raise()

    def node_count(self) -> int:
        self._raise()

    def edge_count(self) -> int:
        self._raise()

    def mark_owned(self, objectid: str) -> None:
        self._raise()

    def owned_ids(self) -> list[str]:
        self._raise()

    def crown_jewels(self) -> list[str]:
        self._raise()

    def reachability(self, hop_cap: int = DEFAULT_HOP_CAP) -> int:
        self._raise()

    def paths_to_jewels(self, objectid: str, hop_cap: int = DEFAULT_HOP_CAP,
                        ties: bool = False) -> list[list[tuple[str, str, str]]]:
        self._raise()

    def edge_frequency(self, hop_cap: int = DEFAULT_HOP_CAP) -> dict[tuple[str, str, str], int]:
        self._raise()

    def add_edge(self, src: str, dst: str, rel: str,
                 props: dict[str, Any] | None = None) -> bool:
        self._raise()

    def cut(self, src: str, dst: str, rel: str) -> int:
        self._raise()

    def profile(self, query: str, params: dict[str, Any] | None = None) -> str:
        self._raise()

    def receipt(self) -> dict[str, Any]:
        self._raise()

    # the optional seams the console and scoring consult via getattr — both
    # raise the outage rather than 500 with a misleading TypeError
    def user_objectids(self) -> list[str]:
        self._raise()

    def scratch_copy(self, scratch_name: str) -> "GraphPort":
        self._raise()


# ---------------------------------------------------------------------------
# audit7/perf-api: the fold layer.
#
# Every folded query below is DERIVED from FalkorGraphPort's module constants
# (the load-bearing queries of the product) by guarded string surgery. If a
# future port changes any constant's shape, the build raises
# _FoldUnsupported, the handlers fall back to the original port-method code,
# and the equivalence suite (tests/test_console_perf_folds.py) fails loudly on
# the live engine. The fold may never answer anything the slow path would not.
# ---------------------------------------------------------------------------

class _FoldUnsupported(Exception):
    """The folded dialect cannot be built from the port's current query
    constants — callers fall back to the unfused port-method path."""


_ARM_RETURN = "RETURN DISTINCT o.objectid AS oid"
_ARM_RETURN_PATHS = "RETURN o.objectid AS oid, t.objectid AS target, p"
_ARM_OWNED_MATCH = "MATCH (o {{owned: true}}), "
_BENIGN_PRINCIPAL_MATCH = "MATCH (o:User), "
_ARM_WITH = " WITH o, t, shortestPath"
_BENIGN_SAMPLE_PRED = "o.objectid IN $sample AND ("

_fold_cache: dict[str, Any] = {}


def _swap(text: str, old: str, new: str, what: str) -> str:
    """Guarded replace: a constant that drifted raises _FoldUnsupported
    instead of silently building a query with different semantics."""
    if old not in text:
        raise _FoldUnsupported(f"{what}: template drifted, {old!r} not found")
    return text.replace(old, new, 1)


def _constant_prefix(query: str, what: str) -> tuple[str, str]:
    """(MATCH...WHERE prefix, node variable) of a port constant — everything
    before its RETURN. The fold re-uses the port's own predicates verbatim."""
    if " RETURN" not in query:
        raise _FoldUnsupported(f"{what}: no RETURN clause to split on")
    prefix = query.split(" RETURN")[0]
    import re as _re

    m = _re.match(r"[\w\s]*MATCH \((\w+)", prefix)
    if not m:
        raise _FoldUnsupported(f"{what}: cannot read the node variable")
    return prefix, m.group(1)


def _fold_probe_query() -> str:
    """ONE round-trip returning (group jewels, azure jewels, owned, nodes,
    edges) — the whole /api/state substrate plus its own cache signature.

    Stage 1 aggregates the Group-jewel scan (always one row, even on zero
    matches — collect() over no rows is []); every later stage is an OPTIONAL
    MATCH so a zero-match estate can never collapse the row (live-verified on
    falkordb 6.0.0: an all-zero probe answers one row, not zero).
    """
    q = _fold_cache.get("probe")
    if q is not None:
        return q
    jp, jv = _constant_prefix(JEWELS_QUERY, "JEWELS_QUERY")
    ap, av = _constant_prefix(AZ_JEWELS_QUERY, "AZ_JEWELS_QUERY")
    op, ov = _constant_prefix(OWNED_QUERY, "OWNED_QUERY")
    built = " ".join([
        jp + f" WITH collect({jv}.objectid) AS gj",
        "OPTIONAL " + ap + f" WITH gj, collect({av}.objectid) AS aj",
        "OPTIONAL " + op + f" WITH gj, aj, collect({ov}.objectid) AS owned",
        "OPTIONAL MATCH (m) WITH gj, aj, owned, count(m) AS nodes",
        "OPTIONAL MATCH ()-[r]->() RETURN gj, aj, owned, nodes, count(r) AS edges",
    ])
    _fold_cache["probe"] = built
    return built


def _fold_path_arm_templates() -> tuple[str, ...]:
    """The reachability arms with the DISTINCT RETURN widened to also return
    the jewel and the path — one row per (owned, jewel) pair, the same
    per-pair shortestPath the canonical paths_to_jewels form evaluates."""
    t = _fold_cache.get("path_arms")
    if t is not None:
        return t
    built = tuple(
        _swap(arm, _ARM_RETURN, _ARM_RETURN_PATHS, "reachability arm")
        for arm in REACHABILITY_ARM_TEMPLATES
    )
    _fold_cache["path_arms"] = built
    return built


def _fold_benign_arm_templates() -> tuple[str, ...]:
    """The same arms, re-anchored from ``{owned: true}`` to a $sample list of
    non-owned User principals — the benign-usage (collateral) measurement,
    one batched pair of round-trips instead of one paths_to_jewels call per
    sampled principal (measured 175+ round-trips on the sample estate)."""
    t = _fold_cache.get("benign_arms")
    if t is not None:
        return t
    built = []
    for arm in REACHABILITY_ARM_TEMPLATES:
        q = _swap(arm, _ARM_OWNED_MATCH, _BENIGN_PRINCIPAL_MATCH, "benign arm match")
        q = _swap(q, "WHERE ", "WHERE " + _BENIGN_SAMPLE_PRED, "benign arm sample")
        q = _swap(q, _ARM_WITH, ")" + _ARM_WITH, "benign arm predicate close")
        q = _swap(q, _ARM_RETURN, _ARM_RETURN_PATHS, "benign arm return")
        built.append(q)
    built = tuple(built)
    _fold_cache["benign_arms"] = built
    return built


def _estate_probe(port: GraphPort) -> tuple[int, int, list[str], list[str]] | None:
    """The folded estate snapshot: (nodes, edges, owned sorted, jewels sorted)
    in ONE engine call, or None when this port does not speak the folded
    dialect (engine-free fake ports, an engine that rejected the shape) —
    the caller then answers through the original port-method path. Engine
    OUTAGES are never swallowed: they propagate to the shared 503 handler."""
    graph = getattr(port, "graph", None)
    query = getattr(graph, "query", None)
    if query is None:
        return None
    try:
        res = query(_fold_probe_query(), timeout=60000)
        row = res.result_set[0] if getattr(res, "result_set", None) else None
        if not row or len(row) != 5:
            return None
        jewels = sorted(str(x) for x in list(row[0]) + list(row[1]))
        owned = sorted(str(x) for x in row[2])
        return int(row[3]), int(row[4]), owned, jewels
    except ENGINE_ERRORS:
        raise
    except _FoldUnsupported:
        return None
    except Exception:
        return None


def _arms_ok(port: GraphPort) -> bool:
    """May the console's cross-product ARM folds run on this port?

    audit8/fix-code, F900 (production): the console's folded arms
    (_arm_reach / _arm_pair_paths / _benign_pair_paths) are the SAME
    cross-product WITH-shortestPath forms the port gates on the engine
    version — on engines < falkordb 6.0.0 (the deployed managed Cloud
    4.22.0) those forms undercount or return nothing, which is exactly how
    production served reach 0 / paths [] with an owned principal. The
    console therefore applies the port's own probe result:
    ``FalkorGraphPort._modern_engine`` (probed once via MODULE LIST).
    Ports WITHOUT the attribute — every engine-free fake port of the
    resilience suite, injected stubs — are conservatively False and answer
    through the original port-method path, which is the path they already
    take (their probe answers nothing) and the path their contracts pin.
    build_app resolves this ONCE per app (see ``arms_fold_ok`` there) so
    the MODULE LIST probe never lands inside a measured request sequence
    (the round-trip receipts pin caught exactly that: cold /api/state
    4 -> 5). On a modern engine nothing changes: the folds stay active and
    the equivalence suite (tests/test_console_perf_folds.py) keeps proving
    fold == port methods.
    """
    return bool(getattr(port, "_modern_engine", False))


def _arm_reach(port: GraphPort, owned: list[str], jewels: list[str],
               hop_cap: int = DEFAULT_HOP_CAP) -> int:
    """port.reachability()'s exact two-arm computation, minus its internal
    re-reads of owned/crown_jewels the caller already holds. Same arm
    queries (REACHABILITY_ARM_TEMPLATES), same owned-jewel self-pair rule."""
    reached: set[str] = set()
    pattern = cypher_traversal_pattern(hop_cap)
    for arm in REACHABILITY_ARM_TEMPLATES:
        res = port.graph.query(arm.format(pattern=pattern), timeout=60000)
        reached.update(str(row[0]) for row in res.result_set)
    jewel_set = set(jewels)
    reached.update(o for o in owned if o in jewel_set)
    return len(reached)


def _arm_pair_paths(port: GraphPort, hop_cap: int) -> dict[tuple[str, str], list[tuple[str, str, str]]]:
    """Every (owned principal, jewel) canonical shortest path in TWO queries
    — the same WITH-clause shortestPath paths_to_jewels evaluates per pair,
    hop-cap and traversal-set guards included (no-ops for the canonical
    form, exactly like the port's own guard)."""
    pattern = cypher_traversal_pattern(hop_cap)
    out: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for tmpl in _fold_path_arm_templates():
        res = port.graph.query(tmpl.format(pattern=pattern), timeout=60000)
        for row in res.result_set:
            hops = _row_to_hops(row[2])
            if not hops:
                continue
            if len(hops) > hop_cap or any(
                rel not in TRAVERSAL_RELS_SET for _, rel, _ in hops
            ):
                continue
            out[(str(row[0]), str(row[1]))] = hops
    return out


def _benign_pair_paths(port: GraphPort, sample: list[str],
                       hop_cap: int) -> dict[tuple[str, str], list[tuple[str, str, str]]]:
    """Same shape as _arm_pair_paths, over the benign-usage sample of
    non-owned principals (the collateral estimate's measurement substrate)."""
    pattern = cypher_traversal_pattern(hop_cap)
    out: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for tmpl in _fold_benign_arm_templates():
        res = port.graph.query(tmpl.format(pattern=pattern),
                               {"sample": list(sample)}, timeout=60000)
        for row in res.result_set:
            hops = _row_to_hops(row[2])
            if not hops:
                continue
            if len(hops) > hop_cap or any(
                rel not in TRAVERSAL_RELS_SET for _, rel, _ in hops
            ):
                continue
            out[(str(row[0]), str(row[1]))] = hops
    return out


def _edge_frequency_from_pairs(
    pairs: dict[tuple[str, str], list[tuple[str, str, str]]],
) -> dict[tuple[str, str, str], int]:
    """port.edge_frequency()'s exact counting over the batched pairs: every
    hop of every (principal, jewel) canonical path adds one — occurrence
    counting, not distinct, matching the port's own loop. The multiset is
    order-independent (rank_cut_candidates imposes its own total order), so
    the batched row order cannot change a single number."""
    freq: dict[tuple[str, str, str], int] = {}
    for hops in pairs.values():
        for hop in hops:
            freq[hop] = freq.get(hop, 0) + 1
    return freq


def _benign_usage_from_pairs(
    pairs: dict[tuple[str, str], list[tuple[str, str, str]]],
) -> dict[tuple[str, str, str], int]:
    """scoring.benign_edge_usage()'s exact counting: per sampled principal,
    the DISTINCT hops across that principal's paths each add one — the
    collateral an edge carries is measured in principals, not paths."""
    per_principal: dict[str, set[tuple[str, str, str]]] = {}
    for (oid, _jewel), hops in pairs.items():
        per_principal.setdefault(oid, set()).update(tuple(h) for h in hops)
    usage: dict[tuple[str, str, str], int] = {}
    for distinct in per_principal.values():
        for hop in distinct:
            usage[hop] = usage.get(hop, 0) + 1
    return usage


def _benign_pool_sample(pool: list[str],
                        sample_size: int = BENIGN_SAMPLE_SIZE) -> list[str]:
    """scoring.benign_edge_usage()'s deterministic sampling stride over the
    sorted non-owned pool — replay-identical receipts."""
    step = max(1, len(pool) // sample_size) if pool else 1
    return pool[::step][:sample_size] if pool else []


def build_app(port: GraphPort | None = None) -> FastAPI:
    """Assemble the console. ``port`` is injectable for engine-free tests of
    the HTTP layer (resilience contract); production always builds a
    FalkorGraphPort."""
    load_dotenv()  # .env at the repo root, if present — real environment always wins

    # OpenAPI/Swagger is opt-in (SEVER_DOCS=1). The console is deployed on a
    # public URL, and the rendered schema (/openapi.json, /docs, /redoc) is
    # free attacker recon — full route + CutRequest shape disclosure — with no
    # product value for a demo UI that already renders the same information.
    docs_enabled = os.environ.get("SEVER_DOCS", "").lower() in ("1", "true", "yes")
    app = FastAPI(
        title="SEVER console", version="0.2.0",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    @app.middleware("http")
    async def _security_headers(request, call_next):
        # Deliberately NO CORSMiddleware: with no CORS policy, no origin other
        # than the console itself can READ any API response from a browser
        # (no Access-Control-Allow-Origin is ever emitted), and non-JSON
        # content types already die as 422 at the body parser, so cross-site
        # requests cannot mutate either. This middleware adds the remaining
        # client-side hardening observed missing on the public deployment
        # (audit3/pentest-external): MIME-sniffing, clickjacking, referrer
        # leakage, and transport security for proxied HTTPS deployments
        # (Render/Cloudflare terminate TLS in front of plain-HTTP uvicorn).
        response = await call_next(request)
        # audit M47: the five headers ship from the ONE constant the 413
        # lane also answers with (sever.console.security.SECURITY_HEADERS —
        # the body-cap middleware runs OUTERMOST, so its rejection bypasses
        # this middleware and carries them itself); both lanes read the same
        # bytes and can never drift apart.
        for key, value in SECURITY_HEADERS:
            response.headers[key.decode("latin-1")] = value.decode("latin-1")
        return response
    # body-size cap BEFORE any buffering (audit3/pentest-internal): hostile
    # multi-MB bodies die as 413 without being fully buffered (~4000x the
    # largest schema-capped field; no legitimate request affected).
    app.add_middleware(BodySizeLimitMiddleware)


    @app.exception_handler(RequestValidationError)
    async def _safe_validation_422(request, exc: RequestValidationError):
        # FastAPI echoes the RAW input inside every 422 detail. A lone
        # surrogate in that echo crashes JSONResponse.render (ensure_ascii=
        # False + .encode("utf-8") raises) and turns the schema's own
        # rejection into a 500. Strip the echo and render with
        # ensure_ascii=True so the error path can never be crashed by input.
        errors = [{k: v for k, v in err.items() if k != "input"} for err in exc.errors()]
        body = json.dumps({"detail": errors}, ensure_ascii=True, default=str)
        return Response(content=body, status_code=422, media_type="application/json")

    async def _engine_outage(request, exc: Exception):
        # The engine IS the product: when FalkorDB is unreachable the console
        # fails cleanly — machine-readable 503 JSON. Pre-fix this surfaced as
        # a bare 500 "Internal Server Error" whose unparseable body left the
        # UI banner showing a JSON-parse artifact instead of the cause
        # (audit3/console-logic, live-verified by killing the engine between
        # /api/finding and /api/cut).
        # audit5/deploy-audit: the raw redis-py message embeds the engine's
        # host:port ("Error connecting to r-....cloud:59719") — surfacing it
        # on the public URL is infrastructure disclosure. Report the
        # exception class only: the cause stays machine-readable
        # (ConnectionError vs TimeoutError) and the banner still says why.
        return JSONResponse(
            status_code=503,
            content={"detail": f"engine unreachable: {type(exc).__name__}"},
        )

    for _exc_cls in ENGINE_ERRORS:
        app.add_exception_handler(_exc_cls, _engine_outage)

    if port is None:
        # Boot-time outage containment (audit8/fix-code, F303): the falkordb
        # client CONSTRUCTOR is the first engine touch on the import path —
        # its eager ``Is_Sentinel`` INFO probe raises when nothing listens,
        # which is what killed ``uvicorn sever.console.app:app`` at import
        # with a raw redis traceback. Contain it: an unreachable engine
        # yields the outage-shim port below, the app still binds, and every
        # request answers through the registered 503 JSON lane (the UI
        # banner state) — the "engine-down containment" README §8 promises.
        # Non-outage construction failures (a misconfigured host that
        # raises anything else) still fail loud: they are configuration
        # errors, not outages.
        try:
            port = FalkorGraphPort(
                host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
                port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
                graph_name=os.environ.get("SEVER_FALKOR_GRAPH", "sever_demo"),
                username=os.environ.get("SEVER_FALKOR_USER"),
                password=os.environ.get("SEVER_FALKOR_PASSWORD"),
            )
        except BOOT_PROBE_ERRORS as exc:
            port = _UnreachablePort(exc)
    # The receipts trail outlives the graph: the CaseLog file is keyed by graph
    # name and survives GRAPH.DELETE by design. It must therefore carry its own
    # estate-lifecycle markers, or history from a previous incarnation of the
    # estate reads as if it happened to this one (audit5/multi-client: the live
    # ledger recorded 10 "removed 1" cuts whose edges exist again today — the
    # estate had been reset out-of-band overnight, and nothing in the trail
    # marked the discontinuity).
    log = CaseLog(os.environ.get("SEVER_FALKOR_GRAPH", "sever_demo"))
    # Boot-time outage containment (audit8/fix-code, F303): the auto-load probe
    # is the second engine touch on the import path, and when the engine is
    # down — or the configured endpoint is a reachable-but-not-FalkorDB RESP
    # server (live-verified: Memurai on 6379 answers the constructor's INFO
    # and then rejects GRAPH.QUERY with a ResponseError) — it used to kill
    # the process with a raw redis traceback BEFORE uvicorn ever bound: the
    # judge-facing "engine-down containment" (README §8) and the 503 contract
    # (§11) were unreachable post-boot-only niceties, and the free-tier Cloud
    # instance stopping after an idle day meant a crash-loop, not
    # containment. Contain instead: the app ALWAYS binds; when the probe
    # fails with the boot-probe family every engine-touching request then
    # answers through the registered 503 JSON lane (the UI banner state),
    # and the attempt is on the receipts trail with outcome unknown — the
    # ledger never invents a success and never loses the attempt.
    # Non-outage boot failures (a missing SEVER_SAMPLE_DIR, corrupt
    # collector JSON) still fail LOUD: those are configuration errors, not
    # outages, and a silent partial boot would hide them.
    try:
        if port.node_count() == 0:
            port.load(parse_ad_dir(os.environ.get(
                "SEVER_SAMPLE_DIR",
                str(Path(__file__).resolve().parents[2] / "data" / "ad_sample"))))
            log.append({
                "step": "estate_loaded",
                "nodes": port.node_count(),
                "edges": port.edge_count(),
                "note": "sample loaded into an empty graph — entries above this line "
                        "describe a previous incarnation of the estate",
            })
    except BOOT_PROBE_ERRORS as exc:
        log.append({
            "step": "console_boot_failed",
            "error": f"engine unreachable at bootstrap: {type(exc).__name__}",
            "outcome": "unknown",
        })

    inv = Investigator(port)
    # F900 follow-up (caught by test_round_trip_receipts on ryzen): resolve
    # the arm-fold gate ONCE, here, at app construction. _arms_ok consults
    # the port's MODULE LIST engine probe — one engine round-trip the first
    # time — and doing that lazily inside a handler landed the probe in the
    # first measured poll sequence (cold /api/state receipts pinned 4, saw
    # 5). Captured at build time the probe is paid during rig setup /
    # production boot — never inside a measured request sequence — and the
    # gate is a plain bool for the app's life: one engine, one answer.
    arms_fold_ok = _arms_ok(port)
    app.state.port = port

    # audit7/perf-api: the /api/state cache discipline. Every mutation
    # endpoint (cut / plan-execute / finding) bumps ``mutation_gen`` — on
    # success, and on the outcome-unknown outage lanes where the attempt may
    # have partially landed. The probe row (nodes, edges, owned, jewels) is
    # the estate generation an out-of-band change shows up in. A cache entry
    # is served only when BOTH the counter and the generation match, so no
    # mutation the product tracks can ever be answered stale (the residual
    # blind spot — an out-of-band rewrite preserving all four aggregates
    # between polls — is documented in the module docstring and outside what
    # any console path can produce).
    mutation_gen: dict[str, int] = {"n": 0}
    state_cache: dict[str, Any] = {"sig": None, "data": None}

    def _touch() -> None:
        mutation_gen["n"] += 1

    def _names(hops: list[tuple[str, str, str]]) -> list[dict[str, str]]:
        out = []
        for s, r, d in hops:
            out.append({
                "src": _name(s), "src_id": s,
                "rel": r,
                "dst": _name(d), "dst_id": d,
            })
        return out

    _name_cache: dict[str, str] = {}

    def _name(oid: str) -> str:
        # audit5/judge-experience: resolve SIDs to human names (a judge must
        # read "T1_TONYMONTANA@PHANTOM.CORP", not "…394-2110"). Cached: names
        # never change on cuts, and the 15s auto-refresh would otherwise
        # re-query the same ids on every poll.
        hit = _name_cache.get(oid)
        if hit is not None:
            return hit
        res = port.graph.query(
            "MATCH (n {objectid: $o}) RETURN n.name AS name LIMIT 1", {"o": oid})
        name = str(res.result_set[0][0]) if res.result_set and res.result_set[0][0] else oid
        _name_cache[oid] = name
        return name

    def _objectid_exists(oid: str) -> bool:
        """Resolves against the loaded estate — the honest-rejection probe:
        a finding about a principal that does not exist is a client error,
        never a narrated phantom no-op."""
        res = port.graph.query(
            "MATCH (n {objectid: $o}) RETURN count(n) AS c", {"o": oid})
        return bool(res.result_set and int(res.result_set[0][0]) > 0)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        # audit5/deploy-audit: Render's HTTP health check needs a 2xx within
        # its 5-second window. Pre-fold /api/state ran 11 sequential engine
        # queries per poll (incl. the full reachability traversal — post-fold
        # it is 3-4 cold / 1 warm, receipts-pinned) and measured 6-24s
        # against FalkorDB Cloud under concurrent load — as the health path
        # it missed its window and Render restarted the instance, and each
        # restart wiped the ephemeral receipts ledger (three boots in ~11
        # minutes, live-verified 2026-10-16 — the AUDIT_DEPLOY §4 boot log
        # spans 00:50:34 to 01:01:47). This probe touches the
        # engine with ONE cheap query (a dead engine still 503s through the
        # shared outage handler, so fail-fast semantics are unchanged) and
        # never appends a receipt, so health-check traffic cannot drown the
        # demo ledger in `state` noise.
        return {
            "status": "ok",
            "backend": "falkordb",
            "graph": port.graph_name,
            "nodes": port.node_count(),
        }

    # audit5/judge-experience: /api/state is polled every 15s by every open
    # console tab. Pre-fix, each poll appended a "state" line to the
    # receipts ledger — 4 lines/minute of identical spam burying the cut and
    # finding receipts a judge actually needs to see. Log state only when it
    # changes; the transition itself is the receipt.
    last_state_log: dict[str, Any] = {"key": None, "missing": False}

    def _state_data_slow() -> dict[str, Any]:
        """The original per-poll computation, verbatim — the fallback every
        handler can always answer through (fake ports in the resilience
        suite take exactly this path), and the equivalence ground truth the
        fold is pinned against. The owned scan is read ONCE (pre-fold it ran
        twice — for ``owned`` and again for ``owned_names``)."""
        owned = port.owned_ids()
        return {
            "backend": "falkordb",
            "graph": port.graph_name,
            "nodes": port.node_count(),
            "edges": port.edge_count(),
            "jewels": port.crown_jewels(),
            "owned": owned,
            # audit5/judge-experience: names for the owned list — the metric
            # sub-line under the big reachability number must read as
            # principals, not as elided SID tails.
            "owned_names": [_name(o) for o in owned],
            "reachability": port.reachability(),
        }

    @app.get("/api/state")
    def state() -> dict[str, Any]:
        # audit7/perf-api: 11 sequential round-trips per poll folded to 4
        # cold (probe + two arms + first-time name lookups) and 1 warm (the
        # probe IS the cache check).
        # The fold refuses itself and falls back to the original path on any
        # dialect mismatch; an engine outage propagates to the 503 handler
        # exactly as before. F900: on engines < 6.0.0 the arms undercount
        # (production served reach 0 with an owned principal) — those
        # engines answer through the port methods, exactly pre-fleet-7.
        probe = _estate_probe(port)
        if probe is None or not arms_fold_ok:
            data = _state_data_slow()
        else:
            nodes, edges, owned, jewels = probe
            sig = (mutation_gen["n"], nodes, edges, tuple(owned), tuple(jewels))
            if state_cache["sig"] == sig and state_cache["data"] is not None:
                # nothing changed by any measure the product tracks: serve
                # the last full computation, zero re-measure, zero staleness
                # (the ledger transition check below still runs on the data).
                data = state_cache["data"]
            else:
                data = {
                    "backend": "falkordb",
                    "graph": port.graph_name,
                    "nodes": nodes,
                    "edges": edges,
                    "jewels": jewels,
                    "owned": owned,
                    "owned_names": [_name(o) for o in owned],
                    "reachability": _arm_reach(port, owned, jewels),
                }
                state_cache["sig"] = sig
                state_cache["data"] = data
        if data["nodes"] == 0:
            # Out-of-band reset detector (audit5/multi-client): the engine-side
            # graph can be deleted or replaced by anything other than this
            # console (operator GRAPH.DELETE, ETL re-ingest) and the receipts
            # file survives it. Without a marker, cuts recorded before the
            # reset contradict the re-loaded estate and a judge cannot see
            # where the story broke.
            # audit M49: the marker fires ONCE per empty episode. Pre-fix,
            # every poll while the estate stayed missing appended BOTH this
            # marker AND a state line (the key below was reset to None behind
            # the change-check's back) — 8 ledger lines/minute per open tab
            # on the exact out-of-band-reset scenario the marker was built
            # for, re-creating the unbounded-growth failure the /api/receipts
            # bound and the change-only state logging were built against.
            if not last_state_log["missing"]:
                log.append({
                    "step": "estate_missing",
                    "note": "graph is empty — the estate was deleted or reset outside "
                            "this console; receipts continuity breaks here",
                })
            last_state_log["missing"] = True
        else:
            # estate back: re-arm the detector so a LATER out-of-band reset
            # marks its own discontinuity.
            last_state_log["missing"] = False
        # audit5/judge-experience: /api/state is polled every 15s by every open
        # console tab — log state only when it CHANGES (the transition itself
        # is the receipt), so poll traffic cannot bury the cut/finding story.
        # audit M49: the key is never reset behind the check's back — the
        # (0,0,0) transition logs once and every further empty poll is silent.
        key = (data["reachability"], data["nodes"], data["edges"])
        if key != last_state_log["key"]:
            last_state_log["key"] = key
            log.append({"step": "state", **{k: data[k] for k in ("reachability", "nodes", "edges")}})

        return data

    @app.get("/api/paths")
    def paths() -> dict[str, Any]:
        # audit7/perf-api: the per-principal loop (O(owned x jewel) pair
        # queries, each re-reading the jewel set) folded to probe + two
        # batched arms — the response's (principal, jewel) order is
        # re-assembled to the port's enumeration order (owned sorted, then
        # jewels sorted), so the UI's render order is byte-identical.
        # F900: the arms are cross-product forms — on engines < 6.0.0 they
        # undercount (production served paths [] with an owned principal),
        # so those engines keep the per-pair port loop, exactly pre-fleet-7.
        probe = _estate_probe(port)
        pairs = None
        if probe is not None and arms_fold_ok:
            try:
                pairs = _arm_pair_paths(port, inv.hop_cap)
            except _FoldUnsupported:
                pairs = None  # arm templates drifted — the original loop answers
        if pairs is None:
            out: dict[str, Any] = {"paths": []}
            for owned in port.owned_ids():
                for path in port.paths_to_jewels(owned):
                    # audit5/judge-experience: _names resolves each hop's
                    # objectid to a human name (src/dst) while keeping the raw
                    # id (src_id/dst_id). Pre-fix the hops rendered as elided
                    # "…394-2110" SIDs that no judge could read — the raw-SID
                    # list comprehension that used to sit here was dead code
                    # (audit8/fix-code: the leftover module-level helper was
                    # removed with it; zero callers repo-wide).
                    out["paths"].append({"principal": _name(owned), "hops": _names(path)})
            return out
        _nodes, _edges, owned, jewels = probe
        out = {"paths": []}
        for o in owned:
            for j in jewels:
                path = pairs.get((o, j))
                if path is not None:
                    out["paths"].append({"principal": _name(o), "hops": _names(path)})
        return out

    @app.get("/api/proposal")
    def proposal() -> list[dict[str, Any]]:
        # audit7/perf-api: inv.propose measured 185 round-trips (the benign
        # sample walked principals one paths_to_jewels call at a time, each
        # re-reading the jewel set). Folded: probe + user pool + two benign
        # arms + two frequency arms — the same ranking inputs
        # (rank_cut_candidates is the port's own scoring function), the same
        # deterministic sample, the same fields.
        # F900: the folded arms are cross-product forms — on engines < 6.0.0
        # they undercount, so those engines answer through inv.propose
        # (port.edge_frequency's per-pair legacy loop), exactly pre-fleet-7.
        probe = _estate_probe(port)
        out: list[dict[str, Any]]
        if probe is None or not arms_fold_ok:
            out = inv.propose(limit=5)
        else:
            _nodes, _edges, owned, _jewels = probe
            lister = getattr(port, "user_objectids", None)
            if lister is None:
                # same lane the original hits inside benign_edge_usage — a
                # port that cannot list principals is a clean TypeError, not
                # an AttributeError 500
                raise TypeError(
                    "benign_edge_usage requires a port that can list principals "
                    "(user_objectids) — supply benign=None for a coverage-only ranking"
                )
            try:
                pool = sorted(set(lister()) - set(owned))
                sample = _benign_pool_sample(pool)
                usage = _benign_usage_from_pairs(
                    _benign_pair_paths(port, sample, inv.hop_cap))
                freq = _edge_frequency_from_pairs(_arm_pair_paths(port, inv.hop_cap))
            except _FoldUnsupported:
                out = inv.propose(limit=5)  # arm templates drifted — original path
            else:
                out = rank_cut_candidates(freq, limit=5, benign=usage)
                for item in out:
                    item["benign_sample"] = {"sampled": len(sample), "pool": len(pool)}
        # audit5/judge-experience: the operator approves a cut between
        # PRINCIPALS, not between opaque SID tails — resolve display names.
        # src/dst keep the raw objectids: the cut API must receive ids.
        for item in out:
            item["src_name"] = _name(item["src"])
            item["dst_name"] = _name(item["dst"])
        return out

    def _plan_folded() -> dict[str, Any] | None:
        """The audit7/perf-api folded /api/plan: scoring.plan_cut_sequence's
        exact greedy k=3 copy+measure algorithm with the same receipt shape,
        run with minimal round-trips from this layer. Same scratch isolation
        (a unique GRAPH.COPY per invocation, dropped in a finally), same
        per-step re-measure-on-the-mutated-copy rule, same verdict semantics,
        same early-stop honesty. Returns None when the port does not speak
        the folded dialect (the caller then runs inv.propose_plan, the
        original loop); engine outages and projection failures propagate to
        the handler's ledgered 503 lanes unchanged. F900: on engines
        < 6.0.0 the arm forms undercount, so the folded plan refuses
        itself there and the caller's inv.propose_plan (scoring's per-pair
        enumeration — the form production proved on the Cloud) answers."""
        hop_cap = inv.hop_cap
        probe = _estate_probe(port)
        if probe is None or not arms_fold_ok:
            return None
        _nodes, _edges, owned, jewels = probe
        copier = getattr(port, "scratch_copy", None)
        if copier is None:
            raise TypeError(
                "plan_cut_sequence requires a port with scratch_copy(name) — "
                "projections are measured on an isolated copy, never simulated"
            )
        # UNIQUE scratch key per invocation (audit5/multi-client): concurrent
        # planners must never share one engine-side copy. Same recipe and
        # recognizable prefix as scoring.plan_cut_sequence so a key leaked by
        # a crashed process stays identifiable and cleanable.
        name = f"{getattr(port, 'graph_name', 'graph')}_plan_scratch_{os.urandom(4).hex()}"
        scratch = copier(name)
        try:
            # audit M50 (parity with scoring.plan_cut_sequence, X53): the
            # base is measured ON the scratch copy — the same isolated-estate
            # state every step's projection is measured on, so "one receipt
            # speaks about one estate state" (scoring.py's documented
            # straddle refusal). Pre-fix the base was measured on the LIVE
            # estate before the GRAPH.COPY, so a mutation landing between the
            # read and the copy made the receipt's base describe a state the
            # steps' projections never built on — exactly the live-read/copy
            # straddle the claimed-parity ground truth documents and refuses.
            base_reach = _arm_reach(scratch, owned, jewels, hop_cap)
            if base_reach == 0:
                return {
                    "k": 3,
                    "method": "graph_copy_remeasure",
                    "base": {"reachability": 0, "owned": owned, "jewels": jewels},
                    "benign_sample_size": BENIGN_SAMPLE_SIZE,
                    "steps": [],
                    "plan_completes_at_step": None,
                    "note": "surface already collapsed (0 breach paths) — nothing to plan",
                }
            # The benign pool cannot change across the plan's steps: the plan
            # only cuts edges on the scratch — nodes, owned flags and the
            # User pool are byte-identical to the live estate the probe just
            # measured. Measuring the sample once is the same numbers the
            # original re-lists every step.
            lister = getattr(scratch, "user_objectids", None)
            if lister is None:
                raise TypeError(
                    "benign_edge_usage requires a port that can list principals "
                    "(user_objectids) — supply benign=None for a coverage-only ranking"
                )
            pool = sorted(set(lister()) - set(owned))
            sample = _benign_pool_sample(pool)
            steps: list[dict[str, Any]] = []
            completes_at: int | None = None
            prev = base_reach
            for i in range(1, 4):  # k = 3 — the documented plan depth
                pairs = _arm_pair_paths(scratch, hop_cap)
                freq = _edge_frequency_from_pairs(pairs)
                if not freq:
                    break
                usage = _benign_usage_from_pairs(
                    _benign_pair_paths(scratch, sample, hop_cap))
                top = rank_cut_candidates(freq, limit=1, benign=usage)[0]
                removed = scratch.cut(top["src"], top["dst"], top["rel"])
                projected = _arm_reach(scratch, owned, jewels, hop_cap)
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
            "k": 3,
            "method": "graph_copy_remeasure",
            "base": {"reachability": base_reach, "owned": owned, "jewels": jewels},
            "benign_sample_size": BENIGN_SAMPLE_SIZE,
            "steps": steps,
            "plan_completes_at_step": completes_at,
            "honesty": (
                "projections are measured on an isolated GRAPH.COPY of the live "
                "estate after each cut; execution re-measures reality per step "
                "and stops at the first drift — a projected number is never the "
                "claim, the live receipt is"
            ),
        }

    @app.get("/api/plan")
    def plan() -> dict[str, Any]:
        # The remediation PLAN: a greedy k=3 cut sequence with per-step
        # MEASURED projections (computed on an isolated GRAPH.COPY — the
        # live estate is never touched by a proposal). The operator reviews
        # the whole sequence, not one edge.
        try:
            try:
                out = _plan_folded()
            except _FoldUnsupported:
                # the folded dialect could not be built from the port's
                # current constants — the original loop answers, same lanes
                out = None
            if out is None:
                out = inv.propose_plan()
        except ENGINE_ERRORS:
            # engine outage mid-plan: record the attempt (outcome unknown),
            # then let the registered 503 handler answer — same contract as
            # finding_failed/cut_failed.
            log.append({"step": "plan_failed",
                        "error": "engine unreachable mid-plan", "outcome": "unknown"})
            raise
        except Exception as e:
            # Any other projection failure (an engine-side graph-lifecycle
            # race, a scratch collision, an internal bug) must still leave the
            # ATTEMPT on the receipts trail. Pre-fix, a failed /api/plan
            # vanished without a ledger entry — an invisible hole for a judge
            # reconstructing the story (audit5/multi-client: concurrent
            # planners 500'd with no trace).
            log.append({"step": "plan_failed",
                        "error": f"plan projection failed: {e}", "outcome": "unknown"})
            raise HTTPException(
                status_code=503,
                detail=f"plan projection failed — engine graph lifecycle race, retry: {e}",
            )
        # mirror onto the console receipts ledger like every other agent
        # step — the trail must show what was proposed, not only what ran
        log.append({"step": "plan", "plan": out})
        return out

    @app.post("/api/plan/execute")
    def plan_execute(req: PlanExecuteRequest) -> dict[str, Any]:
        # Gate check FIRST, exactly like /api/cut: an unapproved caller
        # learns nothing about the plan's steps or rel validity.
        if req.approved is not True:
            raise HTTPException(status_code=403, detail="plan execution requires explicit human approval")
        plan = {
            "steps": [
                {
                    "step": i + 1,
                    "cut": {"src": s.src, "rel": s.rel, "dst": s.dst},
                    "projected_reachability": s.projected_reachability,
                }
                for i, s in enumerate(req.steps)
            ]
        }
        try:
            # audit M51 (X54): forward the operator's decision into the
            # agent-layer gate (same wiring as /api/cut above and the flow
            # path flow.py::resume_investigation — every gate sees the value).
            result = inv.execute_plan(plan, approved_by=req.approved_by,
                                      require_explicit_approval=req.approved)
        except ValueError as e:
            # Only reachable with a schema-valid but unknown rel: the gate
            # above already handled the not-approved case, and the engine's
            # closed-vocabulary guard rejects the rel before any Cypher runs
            # (same contract as /api/cut: client error -> 400, not a 500).
            # Steps before the failing one may already have landed — the
            # cache generation must not survive a partially executed plan.
            _touch()
            raise HTTPException(status_code=400, detail=str(e))
        except ENGINE_ERRORS:
            # Engine died mid-plan: some steps may have landed — outcome
            # unknown, honestly recorded, the ledger never invents a success.
            _touch()
            log.append({"step": "plan_execute_failed",
                        "approved_by": req.approved_by,
                        "error": "engine unreachable mid-plan", "outcome": "unknown"})
            raise
        _touch()
        log.append({"step": "plan_execute", "result": result})
        return result


    @app.post("/api/finding")
    def finding(req: FindingRequest) -> dict[str, Any]:
        # Honest rejection (audit3/console-logic): a finding is about real
        # principals of the loaded estate. Pre-fix, a breach on a nonexistent
        # objectid was a 200 phantom no-op whose narration claimed "this
        # principal is now assumed controlled" (live-verified).
        if not _objectid_exists(req.subject):
            raise HTTPException(
                status_code=400,
                detail=f"unknown subject: no principal with objectid {req.subject!r} in the estate",
            )
        if req.target is not None and not _objectid_exists(req.target):
            raise HTTPException(
                status_code=400,
                detail=f"unknown target: no principal with objectid {req.target!r} in the estate",
            )
        f = Finding(
            # 4 random bytes (8 hex chars): the old 2-byte id space (65,536)
            # collides visibly in the ledger after a few hundred findings.
            id=f"F-{os.urandom(4).hex()}",
            kind=req.kind, subject=req.subject,
            target=req.target, rel=req.rel, grants_edge=bool(req.target and req.rel),
        )
        try:
            report = inv.triage(f)
        except ValueError as e:
            # An invalid rel (e.g. lowercase, spaces, injection attempt) is a
            # CLIENT error — the injection guard in FalkorGraphPort.add_edge
            # rejects it before any Cypher runs. It must surface as a 400,
            # not an unhandled 500 with a stack trace. Nothing reached the
            # engine, so no cache invalidation is needed.
            raise HTTPException(status_code=400, detail=str(e))
        except ENGINE_ERRORS:
            # The engine died mid-triage: the finding may have partially
            # reached the graph (apply_finding is a single atomic MERGE, but
            # the caller cannot know). Record the attempt with outcome
            # unknown — the receipts trail never invents a success, never
            # loses the attempt, and never corrupts a line.
            _touch()
            log.append({"step": "finding_failed", "finding": f.id, "kind": f.kind,
                        "subject": f.subject,
                        "error": "engine unreachable mid-triage", "outcome": "unknown"})
            raise
        _touch()
        log.append({"step": "finding", "finding": f.id, "kind": f.kind, "triage": report.as_dict()})
        story = narrate(f)
        return {
            "finding": f.id,
            "kind": f.kind,
            "technique": f"{story.technique_id} {story.technique}",
            "narration": story.narration,
            "simulated": True,  # findings stream is a labeled breach-timeline replay, not live telemetry
            "applied": report.applied,
            "reachability": report.after["reachability"],
            # audit5/judge-experience: the replay estate loads pre-breached,
            # so both demo buttons often change nothing — the UI must be able
            # to SHOW "1 → 1, no surface change" instead of leaving the judge
            # wondering whether the click worked.
            "reachability_before": report.before["reachability"],
        }

    @app.post("/api/cut")
    def cut(req: CutRequest) -> dict[str, Any]:
        # The gate check comes FIRST: an unapproved caller learns nothing
        # about rel validity (no oracle without approval).
        if req.approved is not True:
            raise HTTPException(status_code=403, detail="interdiction requires explicit human approval")
        try:
            # audit M51 (X54): the operator's decision is forwarded INTO the
            # agent-layer gate — ``require_explicit_approval`` — so the gate
            # below the handler is actually in the loop on the HTTP path.
            # Pre-fix the parameter was never passed, so the investigator's
            # ``True`` default auto-satisfied it and the handler's own
            # identity check was the ONLY layer standing (the README claims
            # "all fail closed at every layer" — the agent gate was
            # structurally inert here). Defense-in-depth restored:
            # req.approved is True here by construction, but a weakened or
            # removed handler gate now still meets a live agent gate below it.
            receipt = inv.approve_and_cut(req.src, req.dst, req.rel,
                                           approved_by=req.approved_by,
                                           require_explicit_approval=req.approved)
        except ValueError as e:
            # Only reachable with an invalid rel: the gate above already
            # handled the not-approved case, and FalkorGraphPort.cut rejects
            # bad rels before any Cypher runs. Client error -> 400, not 500.
            # Nothing reached the engine — no cache invalidation needed.
            raise HTTPException(status_code=400, detail=str(e))
        except ENGINE_ERRORS:
            # Engine died mid-cut (audit3/console-logic: live-verified by
            # killing FalkorDB between /api/finding and /api/cut). The
            # DELETE may or may not have landed — outcome unknown, honestly
            # recorded; the ledger stays valid and complete.
            _touch()
            log.append({"step": "cut_failed",
                        "cut": {"src": req.src, "dst": req.dst, "rel": req.rel},
                        "approved_by": req.approved_by,
                        "error": "engine unreachable mid-cut", "outcome": "unknown"})
            raise
        _touch()
        log.append({"step": "cut", "receipt": receipt})
        return receipt

    @app.get("/api/receipts")
    async def receipts(limit: int = 200) -> list[dict[str, Any]]:
        # Bounded tail (audit5/live-e2e): the ledger is append-only and grows
        # with every poll — every /api/state appends a line, so a day of
        # auto-refresh plus operator traffic makes the full-ledger response
        # grow without bound until the public deployment's worker died on it
        # (live 502s, Oct 16 06:15Z). The UI renders the newest 40; the API
        # ships the newest ``limit`` events (newest-last, unchanged order).
        # The full file stays on disk for forensics — it is never the HTTP
        # payload.
        limit = max(1, min(limit, 5000))
        events = log.read()
        return events[-limit:] if limit < len(events) else events

    # expose for tests/teardown
    build_app.port_obj = port
    return app


if os.environ.get("SEVER_CONSOLE_NO_BOOTSTRAP") == "1":
    # engine-free test import (audit3 resilience suite): the module-level app
    # is skipped and the test builds one explicitly with an injected port —
    # production (uvicorn) never sets this and always bootstraps.
    app = None  # type: ignore[assignment]
else:
    app = build_app()
