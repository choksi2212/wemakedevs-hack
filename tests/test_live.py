"""Live FalkorDB tests — run ONLY when a live engine is reachable.

    SEVER_LIVE_FALKOR=1 python -m pytest tests/test_live.py

Covers the full hero beat on the real engine: load parity, reachability parity
with the mock engine, the human-gated interdiction cascade, and receipts.
These tests are the "mock == live" parity guarantee the README claims.
"""
from __future__ import annotations

import os

import pytest

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("SEVER_LIVE_FALKOR") != "1",
        reason="live engine tests are opt-in (SEVER_LIVE_FALKOR=1)",
    ),
    pytest.mark.skipif(
        not os.path.isdir(os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample")),
        reason="sample data not present",
    ),
]

from sever.core.falkor_port import FalkorGraphPort  # noqa: E402
from sever.core.mock_port import MockGraphPort  # noqa: E402
from sever.agent.investigator import Investigator  # noqa: E402
from sever.findings.stream import Finding  # noqa: E402
from sever.etl.ad_collectors import parse_ad_dir  # noqa: E402

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"


@pytest.fixture(scope="module")
def normalized():
    return parse_ad_dir(os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample"))


@pytest.fixture(scope="module")
def live(normalized):
    graph_name = os.environ.get("SEVER_LIVE_GRAPH", "sever_test_live")
    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=graph_name,
    )
    port.load(normalized)
    yield port
    # teardown: drop the test graph (GRAPH.DELETE returns node count)
    port.graph.client.execute_command("GRAPH.DELETE", graph_name)


def test_load_parity(live, normalized):
    assert live.node_count() == normalized.stats["node_count"]
    assert live.edge_count() == normalized.stats["edge_count"]


def test_reachability_parity_with_mock(live, normalized):
    mock = MockGraphPort()
    mock.load(normalized)
    live.mark_owned(HERO)
    mock.mark_owned(HERO)
    assert live.crown_jewels() == mock.crown_jewels()
    assert live.reachability() == mock.reachability() == 1


def test_live_paths_and_cascade(live):
    paths = live.paths_to_jewels(HERO)
    assert paths, "canonical shortest path must exist on the live engine"
    assert all(hop[1] for path in paths for hop in path)  # every hop carries a rel type
    inv = Investigator(live)
    report = inv.triage(Finding("F-L1", "credential_breach", HERO))
    assert report.after["reachability"] == 1
    assert report.proposal, "agent must propose cuts against the live engine"
    rounds = 0
    while live.reachability() > 0 and rounds < 4:
        prop = inv.propose(limit=3)
        if not prop:
            break
        top = prop[0]
        receipt = inv.approve_and_cut(top["src"], top["dst"], top["rel"])
        assert receipt["cut"]["relationships_removed"] >= 1
        assert receipt["requery_ms"] is not None
        rounds += 1
    assert live.reachability() == 0, f"cascade must collapse within {rounds} gated cuts"
