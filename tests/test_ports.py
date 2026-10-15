"""GraphPort tests — mock engine against REAL sample data, falkor query-shape checks.

The hero scenario is the measured demo beat (see docs/DEMO_SCRIPT):
T1_TONYMONTANA@PHANTOM.CORP owns 10 shortest-paths to Domain Admins;
the single top-frequency edge (GENERIC_ALL -> DF-MS-SHS) collapses all 10.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from sever.core.falkor_port import (
    CUT_COUNT_QUERY_TEMPLATE,
    CUT_DELETE_QUERY_TEMPLATE,
    JEWELS_QUERY,
    MARK_OWNED_QUERY,
    PATH_QUERY_TEMPLATE,
    REACHABILITY_METHOD,
    FalkorGraphPort,
)
from sever.core.jewels import TRAVERSAL_RELS, cypher_traversal_pattern
from sever.core.mock_port import MockGraphPort
from sever.etl.ad_collectors import parse_ad_dir

SAMPLE_DIR = os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample")
pytestmark = pytest.mark.skipif(
    not Path(SAMPLE_DIR).is_dir(), reason=f"sample data not present at {SAMPLE_DIR}"
)

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"  # T1_TONYMONTANA@PHANTOM.CORP


@pytest.fixture(scope="module")
def port():
    g = parse_ad_dir(SAMPLE_DIR)
    p = MockGraphPort()
    p.load(g)
    return p


def test_load_counts(port):
    assert port.node_count() == 1480
    assert port.edge_count() == 12437


def test_crown_jewels(port):
    jewels = port.crown_jewels()
    assert len(jewels) == 5
    assert all(j.endswith(("-512", "-519")) for j in jewels)


def test_hero_baseline(port):
    port.mark_owned(HERO)
    assert port.reachability() == 1
    assert len(port.paths_to_jewels(HERO)) == 10
    assert port.owned_ids() == [HERO]


def test_hero_edge_frequency_ranking(port):
    freq = port.edge_frequency()
    assert freq
    top = max(freq.items(), key=lambda kv: kv[1])
    (src, rel, dst), count = top
    assert src == HERO
    assert rel == "GENERIC_ALL"
    assert count == 10  # on every one of the 10 shortest paths


def test_hero_cut_collapses_everything(port):
    freq = port.edge_frequency()
    (src, rel, dst), _ = max(freq.items(), key=lambda kv: kv[1])
    removed = port.cut(src, dst, rel)
    assert removed >= 1
    assert port.reachability() == 0
    assert port.paths_to_jewels(HERO) == []
    # idempotent second cut: no-op
    assert port.cut(src, dst, rel) == 0
    # receipt reflects the collapse
    assert port.receipt()["reachability"] == 0


# ---- FalkorGraphPort: query shapes + injected-client behavior ----


def test_query_constants_shape():
    pattern = cypher_traversal_pattern(12)
    assert "MEMBER_OF" in pattern and "GENERIC_ALL" in pattern and "*..12" in pattern
    assert "shortestPath" in REACHABILITY_METHOD  # per-pair existence count
    path_q = PATH_QUERY_TEMPLATE.format(pattern=pattern)
    assert path_q.startswith("MATCH p = shortestPath((")
    assert "$oid" in path_q and "$target" in path_q
    assert "$src" in CUT_COUNT_QUERY_TEMPLATE.format(rel="GENERIC_ALL")
    assert "DELETE r" in CUT_DELETE_QUERY_TEMPLATE.format(rel="GENERIC_ALL")
    assert "SET n.owned = true" in MARK_OWNED_QUERY
    assert "ENDS WITH" in JEWELS_QUERY


class _RecordingClient:
    """Stand-in for falkordb Graph object. Returns queued results, records calls."""

    def __init__(self, results=None):
        from collections import deque

        self.calls: list[tuple[str, dict | None]] = []
        self._results = deque(results or [])

    def query(self, query, params=None, timeout=None):
        self.calls.append((query, params))

        class _R:
            result_set = [self._results.popleft()] if self._results else [[0]]

        return _R()


def test_falkor_cut_uses_count_then_delete():
    rec = _RecordingClient(results=[[1]])  # count query returns 1
    port = FalkorGraphPort(client=rec)
    deleted = port.cut("S-src", "S-dst", "GENERIC_ALL")
    assert deleted == 1
    queries = [q for q, _ in rec.calls]
    assert any("count(r)" in q for q in queries)
    assert any("DELETE r" in q for q in queries)
    assert all((p or {}).get("src") == "S-src" and (p or {}).get("dst") == "S-dst" for _, p in rec.calls)
