"""Findings stream + ATT&CK map — stream determinism is DB-free; every
graph-mutating assertion runs on the REAL engine (tiny dedicated estates)."""
from __future__ import annotations

import pytest

from tests.conftest import requires_engine, drop_graph
from sever.agent.llm import OfflineNarrator  # noqa: F401  (import integrity check)
from sever.findings.attack_map import ATTACK_MAP, narrate
from sever.findings.stream import Finding, FindingStream, apply_finding, default_timeline

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"


# ---- DB-free: stream semantics ----


def test_apply_finding_schema():
    f = Finding("F-1", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)
    assert f.grants_edge and f.target == "B" and f.rel == "GENERIC_ALL"


def test_stream_replay_is_sequential_and_exhausts():
    timeline = default_timeline(HERO, "B", "C")
    stream = FindingStream(timeline)
    got = [f.id for f in stream]
    assert got == ["F-001", "F-002", "F-003", "F-004"]
    assert stream.remaining() == 0
    second = FindingStream(default_timeline(HERO, "B", "C"))
    assert [f.id for f in second] == got  # replay-identical


def test_every_timeline_kind_has_attack_map_entry():
    timeline = default_timeline(HERO, "B", "C")
    for f in timeline:
        assert f.kind in ATTACK_MAP, f"kind {f.kind} missing from ATTACK_MAP"
        assert narrate(f).technique_id.startswith("T")


def test_narrate_falls_back_on_unknown_kind():
    f = Finding("F-9", "mystery_kind", "A", detail="odd")
    assert narrate(f).technique_id == "T1595.002"


def test_timeline_f003_targets_real_id_not_placeholder():
    timeline = default_timeline(HERO, "B", "C")
    f003 = timeline[2]
    assert f003.target == "B"
    assert "placeholder" not in (f003.target or "")


# ---- on the REAL engine: finding application mutates the graph ----


@pytest.fixture()
def tiny_port():
    from sever.core.falkor_port import FalkorGraphPort

    name = "sever_test_findings"
    port = FalkorGraphPort(graph_name=name)
    drop_graph(port, name)
    port.graph.query(
        "CREATE (a:User {objectid: 'A', name: 'alice', owned: false}), "
        "(b:Computer {objectid: 'B', name: 'srv'}), "
        "(c:Group {objectid: 'S-1-5-21-t-512', name: 'domain admins'})",
    )
    port.graph.query(
        "MATCH (a:User {objectid: 'A'}), (c:Group {objectid: 'S-1-5-21-t-512'}) "
        "CREATE (a)-[:MEMBER_OF]->(c)",
    )
    yield port
    drop_graph(port, name)


@requires_engine
def test_apply_finding_adds_edge_once_on_engine(tiny_port):
    f = Finding("F-1", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)
    assert apply_finding(tiny_port, f) is True
    assert apply_finding(tiny_port, f) is False  # idempotent
    n = tiny_port.graph.query(
        "MATCH ()-[r:GENERIC_ALL]->() RETURN count(r) AS n").result_set[0][0]
    assert n == 1


@requires_engine
def test_apply_finding_without_grant_is_noop(tiny_port):
    f = Finding("F-2", "kerberoastable_spn", "A")
    assert apply_finding(tiny_port, f) is False
    assert tiny_port.edge_count() == 1  # only the seeded MEMBER_OF
