"""Case-memory tests — interrupt-based human gate, checkpoint resume, ledger."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("langgraph")
from langgraph.checkpoint.memory import MemorySaver

from sever.core.mock_port import MockGraphPort
from sever.etl.ad_collectors import parse_ad_dir
from sever.findings.stream import Finding
from sever.memory.flow import (
    CaseLog,
    build_flow,
    resume_investigation,
    start_investigation,
)

SAMPLE_DIR = os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample")
pytestmark = pytest.mark.skipif(
    not Path(SAMPLE_DIR).is_dir(), reason="sample data not present"
)

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"


@pytest.fixture()
def port():
    g = parse_ad_dir(SAMPLE_DIR)
    p = MockGraphPort()
    p.load(g)
    return p


def test_flow_pauses_at_gate_and_resumes_with_approval(port):
    checkpointer = MemorySaver()
    flow = build_flow(port, checkpointer=checkpointer)

    pending = start_investigation(flow, Finding("F-1", "credential_breach", HERO), "case-A")
    # paused BEFORE the cut: proposal visible, nothing mutated yet
    assert pending["proposal"], "ranked proposal must be visible at the gate"
    assert pending["step"] == "awaiting_approval"
    assert port.reachability() == 1  # cut not executed

    result = resume_investigation(flow, "case-A", approve=True, approved_by="manas")
    assert result["receipt"]["verdict"] == "collapsed"
    assert result["receipt"]["approved_by"] == "manas"
    assert port.reachability() == 0


def test_kill9_resume_from_fresh_flow_object(port):
    """The ONCALL beat: a NEW process (fresh flow, shared checkpointer) resumes
    the interrupted investigation with zero re-explanation."""
    checkpointer = MemorySaver()
    flow1 = build_flow(port, checkpointer=checkpointer)
    pending = start_investigation(flow1, Finding("F-1", "credential_breach", HERO), "case-B")
    assert pending["proposal"]

    # "kill -9": abandon flow1 entirely; a fresh flow object on the same thread
    flow2 = build_flow(port, checkpointer=checkpointer)
    result = resume_investigation(flow2, "case-B", approve=True)
    assert result["receipt"]["verdict"] == "collapsed"
    assert result["receipt"]["before"]["reachability"] == 1
    assert result["receipt"]["after"]["reachability"] == 0
    # and the triage from the FIRST process is still in the thread state
    assert result["triage"]["finding"] == "F-1"


def test_flow_gate_closed_without_approval(port):
    flow = build_flow(port, checkpointer=MemorySaver())
    start_investigation(flow, Finding("F-1", "credential_breach", HERO), "case-C")
    result = resume_investigation(flow, "case-C", approve=False)
    assert result["step"] == "gate_closed"
    assert "receipt" not in result
    assert port.reachability() == 1  # no mutation without a human yes


def test_case_log_append_and_read(tmp_path):
    log = CaseLog("sever_demo", root=tmp_path)
    log.append({"step": "triaged", "finding": "F-1"})
    log.append({"step": "verified", "cut": "x"})
    events = log.read()
    assert [e["step"] for e in events] == ["triaged", "verified"]
    assert events[0]["ts"]
    assert log.last_step() == "verified"
