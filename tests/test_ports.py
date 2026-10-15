"""GraphPort tests against the REAL engine (no substitutes exist).

Each module loads its own tenant graph once; the hero arc is the scripted,
deterministic sequence the demo runs.
"""
from __future__ import annotations

import pytest

from tests.conftest import make_live_port, requires_engine, requires_sample
from sever.core.falkor_port import (
    AZ_JEWELS_QUERY,
    CUT_COUNT_QUERY_TEMPLATE,
    CUT_DELETE_QUERY_TEMPLATE,
    JEWELS_QUERY,
    MARK_OWNED_QUERY,
    PATH_QUERY_TEMPLATE,
    REACHABILITY_METHOD,
)
from sever.core.jewels import TRAVERSAL_RELS, cypher_traversal_pattern

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"  # T1_TONYMONTANA@PHANTOM.CORP

pytestmark = [requires_engine, requires_sample]


@pytest.fixture(scope="module")
def port():
    p = make_live_port("sever_test_ports")
    yield p
    p.graph.client.execute_command("GRAPH.DELETE", "sever_test_ports")


def test_load_counts(port):
    assert port.node_count() == 1480
    assert port.edge_count() == 12437


def test_crown_jewels(port):
    jewels = port.crown_jewels()
    assert len(jewels) == 5
    assert all(j.endswith(("-512", "-519")) for j in jewels)


def test_hero_reachability_and_paths(port):
    port.mark_owned(HERO)
    assert port.owned_ids() == [HERO]
    assert port.reachability() == 1
    paths = port.paths_to_jewels(HERO)
    assert len(paths) == 5  # one canonical shortest path per reached jewel
    assert all(len(p) > 0 for p in paths)
    assert all(hop[1] in set(TRAVERSAL_RELS) for path in paths for hop in path)


def test_edge_frequency_and_cut_collapses(port):
    freq = port.edge_frequency()
    assert freq
    (src, rel, dst), count = max(freq.items(), key=lambda kv: kv[1])
    assert count >= 5  # on every canonical path to the reached jewels
    removed = port.cut(src, dst, rel)
    assert removed >= 1
    assert port.reachability() == 0
    assert port.paths_to_jewels(HERO) == []
    # idempotent second cut: no-op
    assert port.cut(src, dst, rel) == 0
    assert port.receipt()["reachability"] == 0


def test_profile_returns_execution_plan(port):
    q = PATH_QUERY_TEMPLATE.format(pattern=cypher_traversal_pattern(12))
    out = port.profile(q)
    assert "Project" in out and "ms" in out
