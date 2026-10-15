"""Agent tests — LLM seam (DB-free) + investigator loop on the REAL engine."""
from __future__ import annotations

import json
import os

import pytest

from tests.conftest import make_live_port, requires_engine, requires_sample, drop_graph
from sever.agent.investigator import Investigator, TriageReport
from sever.agent.llm import OfflineNarrator, OpenAICompatLLM, build_llm
from sever.core.scoring import rank_cut_candidates
from sever.findings.stream import Finding

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
ALICE = "S-1-5-21-t-1101"
TIER1 = "S-1-5-21-t-2202"
DA = "S-1-5-21-t-t-512"  # ends -512 -> crown jewel by node id


# ---- LLM seam (DB-free) ----


def test_build_llm_defaults_to_offline_without_env(monkeypatch):
    for var in ("SEVER_LLM_BASE_URL", "SEVER_LLM_API_KEY", "SEVER_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    assert isinstance(build_llm(), OfflineNarrator)


def test_build_llm_uses_env(monkeypatch):
    monkeypatch.setenv("SEVER_LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("SEVER_LLM_API_KEY", "k-test")
    monkeypatch.setenv("SEVER_LLM_MODEL", "test-model")
    llm = build_llm()
    assert isinstance(llm, OpenAICompatLLM)
    assert llm._model == "test-model"


def test_offline_narrator_is_deterministic():
    assert OfflineNarrator().complete("s", "u") == OfflineNarrator().complete("s", "u") == ""


# ---- the human gate: exact-True contract (DB-free) ----

# Every value here is truthy or approval-LOOKING but is not the bool True.
# The gate (``is not True`` identity check) must reject all of them BEFORE
# the port is touched — which is why these tests need no engine.
NON_TRUE_APPROVALS = [
    None,
    False,
    0,
    1,
    1.0,
    "1",
    "true",
    "True",
    "yes",
    "y",
    [True],
    {"approved": True},
    (True,),
]


@pytest.mark.parametrize("bad", NON_TRUE_APPROVALS, ids=repr)
def test_gate_rejects_every_non_true_value(bad):
    inv = Investigator(port=None)  # port=None proves the gate fires first
    with pytest.raises(ValueError, match="explicit human approval"):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=bad)


def test_gate_rejects_sneaky_truthy_types():
    class EvilInt(int):
        """Equal to True (== True) but not the True singleton."""

    class AlwaysYes:
        def __bool__(self) -> bool:
            return True

    inv = Investigator(port=None)
    for bad in (EvilInt(1), AlwaysYes()):
        with pytest.raises(ValueError, match="explicit human approval"):
            inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=bad)


def test_gate_passes_only_on_exact_true():
    inv = Investigator(port=None)
    # The bool True passes the gate and PROCEEDS to the port — with port=None
    # the AttributeError is the proof execution went past the gate check.
    with pytest.raises(AttributeError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=True)
    with pytest.raises(AttributeError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL")  # default is True
    # the gate never mutated anything on the way
    assert inv.case_log == []


# ---- case_log: everything the investigator appends is JSON-serializable ----


def _snapshot_like(reachability: int, owned: list[str], jewels: list[str], nodes: int, edges: int):
    """The exact shape of scoring.snapshot() — ints and str lists only."""
    return {
        "reachability": reachability, "owned": owned, "jewels": jewels,
        "nodes": nodes, "edges": edges,
    }


def test_triage_case_log_entry_is_json_serializable():
    # Exactly what Investigator.triage appends to case_log: report.as_dict().
    report = TriageReport(
        finding=Finding("F-1", "credential_breach", ALICE),
        applied=True,
        before=_snapshot_like(1, [ALICE], [DA], 3, 2),
        after=_snapshot_like(2, [ALICE], [DA], 3, 3),
        narration_technique="T1078.002 Valid Accounts: Domain Accounts",
        narration="Compromised domain credentials confirmed.",
        paths_for_subject=[[(ALICE, "GENERIC_ALL", TIER1)], [(TIER1, "MEMBER_OF", DA)]],
        proposal=rank_cut_candidates(
            {(ALICE, "GENERIC_ALL", TIER1): 2, (TIER1, "MEMBER_OF", DA): 1}, limit=3
        ),
    )
    entry = report.as_dict()
    # strict round-trip: plain json.dumps with NO default= crutch
    assert json.loads(json.dumps(entry)) == entry
    # raw hop tuples never enter the ledger — only their count
    assert entry["paths"] == 2
    assert entry["proposal"] == [
        {"src": ALICE, "rel": "GENERIC_ALL", "dst": TIER1, "paths_on": 2},
        {"src": TIER1, "rel": "MEMBER_OF", "dst": DA, "paths_on": 1},
    ]


def test_cut_case_log_entry_is_json_serializable():
    # Exactly what Investigator.approve_and_cut appends: {"cut": receipt},
    # where receipt is scoring.interdict()'s return plus approved_by/approved_at
    # (see sever/core/scoring.py::interdict). The real receipt is pinned
    # end-to-end on the live engine in test_approved_cut_collapses_and_receipts.
    receipt = {
        "cut": {"src": ALICE, "dst": TIER1, "rel": "GENERIC_ALL", "relationships_removed": 1},
        "before": _snapshot_like(1, [ALICE], [DA], 3, 2),
        "after": _snapshot_like(0, [], [DA], 3, 1),
        "requery_ms": 0.83,
        "verdict": "collapsed",
        "approved_by": "on-call-analyst",
        "approved_at": "2026-10-15T15:00:00",
    }
    entry = {"cut": receipt}
    assert json.loads(json.dumps(entry)) == entry


# ---- investigator on the live engine ----


def _tiny_estate(port):
    """Minimal estate on the real engine: alice -GENERIC_ALL-> tier1 -> DA."""
    port.graph.query(
        "CREATE (:User {objectid: $a, name: 'alice', owned: false}), "
        "(:Group {objectid: $g, name: 'tier1'}), "
        "(:Group {objectid: $da, name: 'domain admins'})",
        {"a": ALICE, "g": TIER1, "da": DA},
    )
    port.graph.query(
        "MATCH (a:User {objectid: $a}), (g:Group {objectid: $g}) CREATE (a)-[:GENERIC_ALL]->(g)",
        {"a": ALICE, "g": TIER1},
    )
    port.graph.query(
        "MATCH (g1:Group {objectid: $g}), (g2:Group {objectid: $da}) CREATE (g1)-[:MEMBER_OF]->(g2)",
        {"g": TIER1, "da": DA},
    )


@pytest.fixture()
def tiny_port():
    from sever.core.falkor_port import FalkorGraphPort

    name = "sever_test_agent_tiny"
    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=name,
    )
    drop_graph(port, name)
    _tiny_estate(port)
    yield port
    drop_graph(port, name)


@requires_engine
def test_triage_marks_breach_owned_and_proposes(tiny_port):
    from sever.findings.stream import Finding

    inv = Investigator(tiny_port)
    report = inv.triage(Finding("F-1", "credential_breach", ALICE))
    assert report.after["owned"] == [ALICE]
    assert report.after["reachability"] == 1
    assert report.paths_for_subject  # alice -> tier1 -> DA
    assert report.proposal
    top = report.proposal[0]
    assert (top["src"], top["rel"]) in {(ALICE, "GENERIC_ALL"), (TIER1, "MEMBER_OF")}


@requires_engine
def test_human_gate_blocks_unapproved_cuts(tiny_port):
    inv = Investigator(tiny_port)
    from sever.findings.stream import Finding

    inv.triage(Finding("F-1", "credential_breach", ALICE))
    with pytest.raises(ValueError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=False)
    with pytest.raises(ValueError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval="yolo")


@requires_engine
def test_approved_cut_collapses_and_receipts(tiny_port):
    inv = Investigator(tiny_port)
    from sever.findings.stream import Finding

    inv.triage(Finding("F-1", "credential_breach", ALICE))
    receipt = inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", approved_by="manas")
    assert receipt["approved_by"] == "manas"
    assert receipt["before"]["reachability"] == 1
    assert receipt["after"]["reachability"] == 0
    assert receipt["verdict"] == "collapsed"
    assert receipt["requery_ms"] is not None
    assert any("cut" in entry for entry in inv.case_log)
    # the REAL receipt and the WHOLE ledger (triage + cut entries) are
    # strictly JSON-serializable — the receipts trail is plain JSON
    assert json.loads(json.dumps(receipt)) == receipt
    assert json.loads(json.dumps(inv.case_log)) == inv.case_log


@requires_engine
@requires_sample
def test_investigator_end_to_end_on_sample():
    port = make_live_port("sever_test_agent_sample")
    try:
        from sever.findings.stream import Finding

        inv = Investigator(port, llm=OfflineNarrator())
        report = inv.triage(Finding("F-1", "credential_breach", HERO))
        assert report.after["reachability"] == 1
        assert report.proposal[0]["paths_on"] >= 5
        cut = report.proposal[0]
        receipt = inv.approve_and_cut(cut["src"], cut["dst"], cut["rel"])
        assert receipt["after"]["reachability"] == 0
        assert receipt["verdict"] == "collapsed"
    finally:
        drop_graph(port, "sever_test_agent_sample")
