"""Agent tests: LLM seam, investigator loop, human gate."""
from __future__ import annotations

import pytest

from sever.agent.investigator import Investigator
from sever.agent.llm import NullLLM, OpenAICompatLLM, build_llm
from sever.core.jewels import DEFAULT_HOP_CAP
from sever.core.mock_port import MockGraphPort
from sever.etl.ad_collectors import NormalizedGraph, parse_ad_dir
from sever.findings.stream import Finding

import os
from pathlib import Path

SAMPLE_DIR = os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample")
HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"


# ---- LLM seam ----


def test_build_llm_defaults_to_null_without_env(monkeypatch):
    for var in ("SEVER_LLM_BASE_URL", "SEVER_LLM_API_KEY", "SEVER_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    assert isinstance(build_llm(), NullLLM)


def test_build_llm_uses_env(monkeypatch):
    monkeypatch.setenv("SEVER_LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("SEVER_LLM_API_KEY", "k-test")
    monkeypatch.setenv("SEVER_LLM_MODEL", "test-model")
    llm = build_llm()
    assert isinstance(llm, OpenAICompatLLM)
    assert llm._model == "test-model"


def test_null_llm_is_deterministic():
    assert NullLLM().complete("s", "u") == NullLLM().complete("s", "u") == ""


# ---- investigator ----


ALICE = "S-1-5-21-t-1101"
TIER1 = "S-1-5-21-t-2202"
DA = "S-1-5-21-t-t-512"  # ends -512 -> crown jewel by node id


def _tiny_port() -> tuple[MockGraphPort, NormalizedGraph]:
    g = NormalizedGraph()
    g.add_node(ALICE, "User", {"name": "alice"})
    g.add_node(TIER1, "Group", {"name": "tier1"})
    g.add_node(DA, "Group", {"name": "domain admins"})
    g.add_edge(TIER1, DA, "MEMBER_OF")          # group nesting
    g.add_edge(ALICE, TIER1, "GENERIC_ALL")     # alice controls tier1
    port = MockGraphPort()
    port.load(g)
    return port, g


def test_triage_marks_breach_owned_and_proposes():
    port, g = _tiny_port()
    inv = Investigator(port)
    report = inv.triage(Finding("F-1", "credential_breach", ALICE))
    assert report.after["owned"] == [ALICE]
    assert report.after["reachability"] == 1
    assert report.paths_for_subject  # alice -> tier1 -> DA
    assert report.proposal  # cut candidates ranked
    top = report.proposal[0]
    assert (top["src"], top["rel"]) in {(ALICE, "GENERIC_ALL"), (TIER1, "MEMBER_OF")}


def test_human_gate_blocks_unapproved_cuts():
    port, _ = _tiny_port()
    inv = Investigator(port)
    inv.triage(Finding("F-1", "credential_breach", ALICE))
    with pytest.raises(ValueError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=False)
    with pytest.raises(ValueError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval="yolo")


def test_approved_cut_collapses_and_receipts():
    port, _ = _tiny_port()
    inv = Investigator(port)
    inv.triage(Finding("F-1", "credential_breach", ALICE))
    receipt = inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", approved_by="manas")
    assert receipt["approved_by"] == "manas"
    assert receipt["before"]["reachability"] == 1
    assert receipt["after"]["reachability"] == 0
    assert receipt["verdict"] == "collapsed"
    assert receipt["requery_ms"] >= 0
    assert any("cut" in entry for entry in inv.case_log)


@pytest.mark.skipif(not Path(SAMPLE_DIR).is_dir(), reason="sample data absent")
def test_investigator_end_to_end_on_sample():
    g = parse_ad_dir(SAMPLE_DIR)
    port = MockGraphPort()
    port.load(g)
    inv = Investigator(port, llm=NullLLM(), hop_cap=DEFAULT_HOP_CAP)
    report = inv.triage(Finding("F-1", "credential_breach", HERO))
    assert report.after["reachability"] == 1
    assert len(report.paths_for_subject) == 10
    assert report.proposal[0]["paths_on"] == 10
    cut = report.proposal[0]
    receipt = inv.approve_and_cut(cut["src"], cut["dst"], cut["rel"])
    assert receipt["after"]["reachability"] == 0
    assert receipt["verdict"] == "collapsed"
