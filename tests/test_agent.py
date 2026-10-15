"""Agent tests — LLM seam (DB-free) + investigator loop on the REAL engine."""
from __future__ import annotations

import pytest

from tests.conftest import make_live_port, requires_engine, requires_sample, drop_graph
from sever.agent.investigator import Investigator
from sever.agent.llm import LLM, OfflineNarrator, OpenAICompatLLM, build_llm

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


@pytest.mark.parametrize(
    "base_url,api_key,model",
    [
        ("", "k", "m"),   # empty base URL
        ("u", "", "m"),   # empty key
        ("u", "k", ""),   # empty model
        ("", "", "m"),
        ("", "k", ""),
        ("u", "", ""),
        ("", "", ""),     # all malformed
    ],
)
def test_build_llm_malformed_env_falls_back_offline(monkeypatch, base_url, api_key, model):
    monkeypatch.setenv("SEVER_LLM_BASE_URL", base_url)
    monkeypatch.setenv("SEVER_LLM_API_KEY", api_key)
    monkeypatch.setenv("SEVER_LLM_MODEL", model)
    assert isinstance(build_llm(), OfflineNarrator)  # any empty field -> offline, never a crash


def test_build_llm_survives_constructor_failure(monkeypatch):
    monkeypatch.setenv("SEVER_LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("SEVER_LLM_API_KEY", "k-test")
    monkeypatch.setenv("SEVER_LLM_MODEL", "test-model")

    class _Unreachable:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("endpoint unreachable")

    monkeypatch.setattr("sever.agent.llm.OpenAICompatLLM", _Unreachable)
    assert isinstance(build_llm(), OfflineNarrator)  # the seam never hard-fails


def test_build_llm_wires_env_into_the_provider(monkeypatch):
    captured = {}

    class _Stub:
        def __init__(self, base_url, api_key, model, timeout=30.0):
            captured.update(base_url=base_url, api_key=api_key, model=model, timeout=timeout)

    monkeypatch.setattr("sever.agent.llm.OpenAICompatLLM", _Stub)
    monkeypatch.setenv("SEVER_LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("SEVER_LLM_API_KEY", "k-test")
    monkeypatch.setenv("SEVER_LLM_MODEL", "test-model")
    llm = build_llm()
    assert isinstance(llm, _Stub)
    assert captured == {
        "base_url": "https://example.test/v1",
        "api_key": "k-test",
        "model": "test-model",
        "timeout": 30.0,
    }


def test_offline_narrator_is_deterministic():
    assert OfflineNarrator().complete("s", "u") == OfflineNarrator().complete("s", "u") == ""


def test_offline_narrator_contract_is_deterministic():
    narrator = OfflineNarrator()
    assert isinstance(narrator, LLM)
    assert narrator.name == "null"
    outs = {OfflineNarrator().complete(f"sys-{i}", f"usr-{i}") for i in range(5)}
    outs |= {
        narrator.complete("", ""),                       # empty prompts
        narrator.complete("ünïcode ✓", "x" * 1000),      # unicode + long input
        narrator.complete("s", "u"),
        narrator.complete("s", "u"),                      # repeat calls
    }
    assert outs == {""}  # every prompt, every instance, every call -> the same silence


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
    port = FalkorGraphPort(graph_name=name)
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
