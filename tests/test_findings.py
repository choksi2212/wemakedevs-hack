"""Findings stream + ATT&CK map — stream determinism and apply_finding
rejection semantics are DB-free (wire-shape checks via an injected client);
every graph-mutating assertion runs on the REAL engine (tiny estates)."""
from __future__ import annotations

import os
import re
import dataclasses
from dataclasses import FrozenInstanceError

import pytest

from tests.conftest import requires_engine, drop_graph, prefixed
from sever.agent.llm import OfflineNarrator  # noqa: F401  (import integrity check)
from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import NormalizedGraph
from sever.findings.attack_map import ATTACK_MAP, narrate
from sever.findings.stream import Finding, FindingStream, apply_finding, default_timeline

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"


# ---- DB-free: stream semantics ----


def test_apply_finding_schema():
    f = Finding("F-1", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)
    assert f.grants_edge and f.target == "B" and f.rel == "GENERIC_ALL"


def test_finding_is_frozen():
    """Finding is a frozen dataclass: no code path — apply_finding included —
    can mutate it. Python enforces this for every caller."""
    f = Finding("F-1", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)
    for attr in ("id", "kind", "subject", "target", "rel", "detail", "grants_edge"):
        with pytest.raises(FrozenInstanceError):
            setattr(f, attr, "mutated")
    # frozen -> hashable and structurally comparable
    assert hash(f) == hash(
        Finding("F-1", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)
    )
    assert f != Finding("F-2", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)


def test_apply_finding_cannot_mutate_the_finding():
    # A non-granting finding never touches the port — port=None is the proof.
    f = Finding("F-2", "kerberoastable_spn", "A")
    assert apply_finding(None, f) is False
    assert (f.grants_edge, f.target, f.rel) == (False, None, None)
    # a granting finding without a target/rel is also a no-op
    half = Finding("F-3", "ace_granted", "A", grants_edge=True)
    assert apply_finding(None, half) is False  # no target, no rel -> no port call


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
    """Owner resolution #4 (audit M69): an unknown kind gets a kind-NEUTRAL
    fallback — never a fabricated ATT&CK label. The pre-fix fallback narrated
    any unmapped kind as 'T1595.002 Active Scanning: Vulnerability Scanning',
    exactly the fabrication schemas.py documents (and the HTTP layer 422s)."""
    f = Finding("F-9", "mystery_kind", "A", detail="odd")
    story = narrate(f)
    assert story.technique_id == "UNMAPPED"
    assert story.technique == "Unmapped finding kind"
    assert "mystery_kind" in story.narration  # the narration names the kind
    assert "T1595" not in story.technique_id  # no fabricated technique id


def test_attack_map_ids_and_names_match_mitre_enterprise():
    # Pinned against attack.mitre.org (Enterprise). Exact ID->name contract:
    # DCSync is T1003.006 (T1003.002 is Security Account Manager), and the
    # official T1558 parent name is "Steal or Forge Kerberos Tickets".
    expected = {
        "credential_breach": ("T1078.002", "Valid Accounts: Domain Accounts"),
        "kerberoastable_spn": ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
        "ace_granted": ("T1098", "Account Manipulation"),
        "dcsync_right": ("T1003.006", "OS Credential Dumping: DCSync"),
        "cross_domain_trust": ("T1482", "Domain Trust Discovery"),
        "cert_esc1": ("T1649", "Steal or Forge Authentication Certificates"),
    }
    assert set(ATTACK_MAP) == set(expected)
    for kind, (technique_id, technique) in expected.items():
        assert ATTACK_MAP[kind].technique_id == technique_id, kind
        assert ATTACK_MAP[kind].technique == technique, kind


def test_attack_map_narrations_and_ids_are_wellformed():
    for kind, narrative in ATTACK_MAP.items():
        assert narrative.narration.strip(), kind
        assert narrative.narration == narrative.narration.strip(), kind
        # canonical ATT&CK wire format: what the UI banner renders
        assert re.fullmatch(r"T\d{4}(?:\.\d{3})?", narrative.technique_id), kind


def test_timeline_f003_targets_real_id_not_placeholder():
    timeline = default_timeline(HERO, "B", "C")
    f003 = timeline[2]
    assert f003.target == "B"
    assert "placeholder" not in (f003.target or "")


# ---- DB-free: stream exhaustion + apply_finding rejection semantics ----


def test_stream_exhaustion_raises_stopiteration():
    stream = FindingStream(default_timeline(HERO, "B", "C"))
    while stream.remaining():
        next(stream)
    assert stream.remaining() == 0
    for _ in range(3):  # an exhausted stream keeps raising — it never wraps around
        with pytest.raises(StopIteration):
            next(stream)
    assert list(stream) == []  # re-iterating a spent stream yields nothing


def test_empty_stream_is_immediately_exhausted():
    stream = FindingStream([])
    assert stream.remaining() == 0
    assert list(stream) == []
    with pytest.raises(StopIteration):
        next(stream)


def test_stream_takes_a_snapshot_of_its_input():
    src = default_timeline(HERO, "B", "C")
    stream = FindingStream(src)
    src.clear()  # caller-side mutations must not affect an armed stream
    assert stream.remaining() == 4
    assert next(stream).id == "F-001"


def test_findings_are_immutable_stream_items():
    f = Finding("F-1", "ace_granted", "A")
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.id = "X"  # replayed timelines can never be rewritten mid-flight


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


def test_apply_finding_noop_paths_never_touch_the_engine():
    port = FalkorGraphPort(client=_RecordingClient())
    assert apply_finding(port, Finding("F-2", "kerberoastable_spn", "A")) is False  # no grant
    assert apply_finding(port, Finding("F-3", "ace_granted", "A", target="B",
                                       rel=None, grants_edge=True)) is False       # rel missing
    assert apply_finding(port, Finding("F-3b", "ace_granted", "A", target="B",
                                       rel="", grants_edge=True)) is False         # rel empty
    assert apply_finding(port, Finding("F-4", "ace_granted", "A", target=None,
                                       rel="GENERIC_ALL", grants_edge=True)) is False  # target missing
    assert apply_finding(port, Finding("F-5", "ace_granted", "A",
                                       rel="GENERIC_ALL", grants_edge=False)) is False  # grant off
    assert port.graph.calls == []


def test_apply_finding_rejects_schema_violating_rel_before_the_engine():
    port = FalkorGraphPort(client=_RecordingClient(results=[[1]]))
    for bad in ("generic_all", "GENERIC_ALL}) DETACH DELETE (n) //", "A B", "A\nB"):
        f = Finding("F-1", "ace_granted", "A", target="B", rel=bad, grants_edge=True)
        with pytest.raises(ValueError):
            apply_finding(port, f)  # the closed rel vocabulary fires before interpolation
    assert port.graph.calls == []  # nothing reached the engine


def test_apply_finding_wire_contract():
    f = Finding("F-77", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)
    # atomic add_edge: one query returns the pre-MERGE edge count (pre=0 -> True)
    port = FalkorGraphPort(client=_RecordingClient(results=[[0]]))
    assert apply_finding(port, f) is True  # edge absent -> MERGE created it
    q, params = port.graph.calls[0]
    assert "OPTIONAL MATCH (s)-[r0:GENERIC_ALL]->(t)" in q
    assert "MERGE (s)-[r:GENERIC_ALL]->(t)" in q
    assert "SET r += $props" in q
    assert "RETURN pre" in q
    assert params == {"src": "A", "dst": "B", "props": {"source": "F-77"}}
    # edge already exists: pre=1 -> False (idempotent re-grant is a no-op)
    port2 = FalkorGraphPort(client=_RecordingClient(results=[[1]]))
    assert apply_finding(port2, f) is False
    assert len(port2.graph.calls) == 1


# ---- on the REAL engine: finding application mutates the graph ----


@pytest.fixture()
def tiny_port():
    from sever.core.falkor_port import FalkorGraphPort

    name = prefixed("sever_test_findings")
    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=name,
    )
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
    # apply_finding only READS the frozen finding — even after two passes
    # through the mutation path, nothing about it changed
    assert f == Finding("F-1", "ace_granted", "A", target="B", rel="GENERIC_ALL", grants_edge=True)
    n = tiny_port.graph.query(
        "MATCH ()-[r:GENERIC_ALL]->() RETURN count(r) AS n").result_set[0][0]
    assert n == 1


@requires_engine
def test_apply_finding_without_grant_is_noop(tiny_port):
    f = Finding("F-2", "kerberoastable_spn", "A")
    assert apply_finding(tiny_port, f) is False
    assert tiny_port.edge_count() == 1  # only the seeded MEMBER_OF
