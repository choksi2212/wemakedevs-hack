"""Findings stream + ATT&CK map tests (deterministic, graph-mutating)."""
from __future__ import annotations

from sever.core.mock_port import MockGraphPort
from sever.etl.ad_collectors import NormalizedGraph
from sever.findings.attack_map import ATTACK_MAP, narrate
from sever.findings.stream import Finding, FindingStream, apply_finding, default_timeline

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"


def _tiny_port() -> MockGraphPort:
    g = NormalizedGraph()
    g.add_node("A", "User", {"name": "alice"})
    g.add_node("B", "Computer", {"name": "srv"})
    g.add_node("C", "Group", {"name": "admins", "objectid": "C"})
    port = MockGraphPort()
    port.load(g)
    return port


def test_apply_finding_adds_edge_once():
    port = _tiny_port()
    f = Finding("F-1", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)
    assert apply_finding(port, f) is True
    assert apply_finding(port, f) is False  # idempotent
    assert port.edge_count() == 1


def test_apply_finding_without_grant_is_noop():
    port = _tiny_port()
    f = Finding("F-2", "kerberoastable_spn", "A")
    assert apply_finding(port, f) is False
    assert port.edge_count() == 0


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
