"""Shared fixtures: every port-dependent test runs against the REAL engine.

There is no in-engine substitute: SEVER's engine is FalkorDB and every test
that touches a graph requires it (docker compose up -d). DB-free units
(ETL parsing, tenant generation, findings schema, LLM seam) run anywhere.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import parse_ad_dir

_REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR", str(_REPO_ROOT / "data" / "ad_sample")
)
ENGINE_REACHABLE = False
try:
    if os.environ.get("SEVER_FALKOR_HOST") is None:
        os.environ.setdefault("SEVER_FALKOR_HOST", "127.0.0.1")
    probe = FalkorGraphPort(
        host=os.environ["SEVER_FALKOR_HOST"],
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name="sever_conftest_probe",
    )
    probe.node_count()
    ENGINE_REACHABLE = True
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
    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=graph_name,
    )
    if load_sample and port.node_count() == 0:
        port.load(parse_ad_dir(SAMPLE_DIR))
    return port


def drop_graph(port, graph_name: str) -> None:
    """Delete a graph idempotently — GRAPH.DELETE on a missing key raises."""
    try:
        port.graph.client.execute_command("GRAPH.DELETE", graph_name)
    except Exception:
        pass
