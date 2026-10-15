"""DB-free guards: Cypher injection protection + query-shape contracts."""
from __future__ import annotations

import pytest

from sever.core.falkor_port import (
    AZ_JEWELS_QUERY,
    CUT_COUNT_QUERY_TEMPLATE,
    CUT_DELETE_QUERY_TEMPLATE,
    JEWELS_QUERY,
    MARK_OWNED_QUERY,
    PATH_QUERY_TEMPLATE,
    REACHABILITY_METHOD,
    FalkorGraphPort,
)
from sever.core.jewels import cypher_traversal_pattern


def test_query_constants_shape():
    pattern = cypher_traversal_pattern(12)
    assert "MEMBER_OF" in pattern and "GENERIC_ALL" in pattern and "*..12" in pattern
    assert "shortestPath" in REACHABILITY_METHOD  # per-pair existence count
    path_q = PATH_QUERY_TEMPLATE.format(pattern=pattern)
    assert path_q.startswith("MATCH (o {objectid: $oid})")
    assert "algo.SPpaths" in path_q and "pathCount: 100" in path_q
    assert "$oid" in path_q and "$target" in path_q
    assert "$src" in CUT_COUNT_QUERY_TEMPLATE.format(rel="GENERIC_ALL")
    assert "DELETE r" in CUT_DELETE_QUERY_TEMPLATE.format(rel="GENERIC_ALL")
    assert "SET n.owned = true" in MARK_OWNED_QUERY
    assert "ENDS WITH" in JEWELS_QUERY and "ENDS WITH" in AZ_JEWELS_QUERY


class _RecordingClient:
    """Stand-in for the falkordb-py graph object (wire-shape unit tests)."""

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
    from sever.core.falkor_port import FalkorGraphPort

    rec = _RecordingClient(results=[[1]])  # count query returns 1
    port = FalkorGraphPort(client=rec)
    deleted = port.cut("S-src", "S-dst", "GENERIC_ALL")
    assert deleted == 1
    queries = [q for q, _ in rec.calls]
    assert any("count(r)" in q for q in queries)
    assert any("DELETE r" in q for q in queries)
    assert all((p or {}).get("src") == "S-src" and (p or {}).get("dst") == "S-dst" for _, p in rec.calls)


def test_cypher_injection_guard():
    from sever.core.falkor_port import FalkorGraphPort

    port = FalkorGraphPort(client=_RecordingClient())
    for evil in ("GENERIC_ALL}) DETACH DELETE (n) //", "a-b-c", "x' OR '1'='1", "",
                 "A}) DETACH", "MATCH (x) DETACH DELETE (x)", "A B"):
        with pytest.raises(ValueError):
            port.add_edge("A", "B", evil)
        with pytest.raises(ValueError):
            port.cut("A", "B", evil)


def test_falkor_cut_uses_count_then_delete():
    rec = _RecordingClient(results=[[1]])  # count query returns 1
    port = FalkorGraphPort(client=rec)
    deleted = port.cut("S-src", "S-dst", "GENERIC_ALL")
    assert deleted == 1
    queries = [q for q, _ in rec.calls]
    assert any("count(r)" in q for q in queries)
    assert any("DELETE r" in q for q in queries)
    assert all((p or {}).get("src") == "S-src" and (p or {}).get("dst") == "S-dst" for _, p in rec.calls)


def test_cypher_injection_guard():
    port = FalkorGraphPort(client=_RecordingClient())
    for evil in ("GENERIC_ALL}) DETACH DELETE (n) //", "a-b-c", "x' OR '1'='1", "",
                 "A}) DETACH", "MATCH (x) DETACH DELETE (x)", "A B"):
        with pytest.raises(ValueError):
            port.add_edge("A", "B", evil)
        with pytest.raises(ValueError):
            port.cut("A", "B", evil)
    # valid vocabulary passes the guard
    port.add_edge("A", "B", "GENERIC_ALL")
    port.cut("A", "B", "MEMBER_OF")
