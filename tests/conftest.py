"""Shared fixtures: every port-dependent test runs against the REAL engine.

There is no in-engine substitute: SEVER's engine is FalkorDB and every test
that touches a graph requires it (docker compose up -d). DB-free units
(ETL parsing, tenant generation, findings schema, LLM seam) run anywhere.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from redis.exceptions import ResponseError

from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import parse_ad_dir

_REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR", str(_REPO_ROOT / "data" / "ad_sample")
)
# Shared-engine hygiene: every engine key tests create can be namespaced
# with one env var, so parallel suites against ONE FalkorDB instance can
# never collide on a graph key or poison each other's receipts. Default:
# no prefix, unchanged behavior. Known un-prefixed exceptions (audit L77),
# both single-suite keys that drop themselves: the console-resilience
# suite's sever_audit3_cl_resil and the boot-outage suite's
# sever_audit8_fixcode_boot; the case-ledger FILES suites write live under
# tmp dirs (root=tmp_path / chdir(tmp_path)), so those are per-test
# isolated and never share the engine either.
_GRAPH_PREFIX = os.environ.get("SEVER_TEST_GRAPH_PREFIX", "")


def prefixed(name: str) -> str:
    """Apply the optional SEVER_TEST_GRAPH_PREFIX to an engine key.

    Idempotent: an already-prefixed name (e.g. port.graph_name handed back
    from make_live_port) is never double-prefixed.
    """
    if _GRAPH_PREFIX and name.startswith(_GRAPH_PREFIX):
        return name
    return _GRAPH_PREFIX + name


def drop_graph(port, graph_name: str) -> None:
    """Delete a graph idempotently — GRAPH.DELETE on a missing key raises.

    Only the engine's missing-key error is swallowed (live-verified on
    falkordb 6.0.0: ResponseError "Invalid graph operation on empty key";
    the "not exist" clause covers the older-engine wording of the same
    case). Every OTHER failure — connection loss, auth, timeout, engine
    fault — re-raises, so a genuine GRAPH.DELETE problem surfaces instead
    of silently poisoning the hermetic starts (audit L78)."""
    try:
        port.graph.client.execute_command("GRAPH.DELETE", prefixed(graph_name))
    except ResponseError as exc:
        if "empty key" not in str(exc) and "not exist" not in str(exc):
            raise


ENGINE_REACHABLE = False
try:
    os.environ.setdefault("SEVER_FALKOR_HOST", "127.0.0.1")
    probe = FalkorGraphPort(
        host=os.environ["SEVER_FALKOR_HOST"],
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=prefixed("sever_conftest_probe"),
    )
    probe.node_count()
    ENGINE_REACHABLE = True
    # node_count()'s GRAPH.QUERY materializes the key when missing
    # (live-verified: FalkorDB creates graph keys on query), so the probe
    # above just re-created sever_conftest_probe — delete it again, or
    # every live-engine pytest session leaks the key on the shared engine
    # (audit M71). GRAPH.RO_QUERY cannot replace the probe itself: it also
    # RAISES on a missing key (live-verified), which would mark a live
    # engine unreachable and silently skip every engine-gated test.
    drop_graph(probe, "sever_conftest_probe")
except Exception:
    ENGINE_REACHABLE = False

requires_engine = pytest.mark.skipif(
    not ENGINE_REACHABLE, reason="requires the live FalkorDB engine (docker compose up -d)"
)
requires_sample = pytest.mark.skipif(
    not Path(SAMPLE_DIR).is_dir(), reason=f"sample data not present at {SAMPLE_DIR}"
)


def make_live_port(graph_name: str, load_sample: bool = True) -> FalkorGraphPort:
    """Fresh graph on the real engine; optionally loaded from the sample."""
    graph_name = prefixed(graph_name)
    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=graph_name,
    )
    if load_sample:
        # hermetic start (audit3/test-forensics flakiness sweep): a leftover
        # graph from a crashed previous run must never silently skip the load
        # and serve stale engine state to the test
        drop_graph(port, graph_name)
        port.load(parse_ad_dir(SAMPLE_DIR))
    return port

