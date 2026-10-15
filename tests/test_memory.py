"""Case-memory tests — resumable flow on the REAL engine; the checkpointer is
LangGraph's MemorySaver for the in-process interrupt test and FalkorDBSaver
for the cross-process beat (scripts/case_memory_live.py demonstrates the
two-process version end to end)."""
from __future__ import annotations

from tests.conftest import drop_graph

import pytest

from tests.conftest import make_live_port, requires_engine, requires_sample
from sever.findings.stream import Finding
from sever.memory.flow import (
    CaseLog,
    build_flow,
    resume_investigation,
    start_investigation,
)

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
pytestmark = [requires_engine, requires_sample]


@pytest.fixture()
def live_port():
    port = make_live_port("sever_test_memory")
    yield port
    drop_graph(port, "sever_test_memory")


def test_flow_pauses_at_gate_and_resumes_with_approval(live_port):
    pytest.importorskip("langgraph")
    from langgraph.checkpoint.memory import MemorySaver

    flow = build_flow(live_port, checkpointer=MemorySaver())

    pending = start_investigation(flow, Finding("F-1", "credential_breach", HERO), "case-A")
    assert pending["proposal"], "ranked proposal must be visible at the gate"
    assert pending["step"] == "awaiting_approval"
    assert live_port.reachability() == 1  # cut not executed

    result = resume_investigation(flow, "case-A", approve=True, approved_by="manas")
    assert result["receipt"]["verdict"] == "collapsed"
    assert result["receipt"]["approved_by"] == "manas"
    assert live_port.reachability() == 0


def test_kill9_resume_from_fresh_flow_object(live_port):
    """The ONCALL beat: a NEW flow object (same engine, same checkpointer)
    resumes the interrupted investigation with zero re-explanation."""
    pytest.importorskip("langgraph")
    from langgraph.checkpoint.memory import MemorySaver

    checkpointer = MemorySaver()
    flow1 = build_flow(live_port, checkpointer=checkpointer)
    pending = start_investigation(flow1, Finding("F-1", "credential_breach", HERO), "case-B")
    assert pending["proposal"]

    flow2 = build_flow(live_port, checkpointer=checkpointer)  # "fresh process"
    result = resume_investigation(flow2, "case-B", approve=True)
    assert result["receipt"]["verdict"] == "collapsed"
    assert result["receipt"]["before"]["reachability"] == 1
    assert result["receipt"]["after"]["reachability"] == 0
    assert result["triage"]["finding"] == "F-1"


def test_flow_gate_closed_without_approval(live_port):
    pytest.importorskip("langgraph")
    from langgraph.checkpoint.memory import MemorySaver

    flow = build_flow(live_port, checkpointer=MemorySaver())
    start_investigation(flow, Finding("F-1", "credential_breach", HERO), "case-C")
    result = resume_investigation(flow, "case-C", approve=False)
    assert result["step"] == "gate_closed"
    assert "receipt" not in result
    assert live_port.reachability() == 1  # no mutation without a human yes


def test_falkordb_saver_checkpointer_roundtrip(live_port):
    """Case memory IN the graph database via FalkorDBSaver (the shipped mode)."""
    saver = pytest.importorskip("langchain_falkordb").checkpoint.FalkorDBSaver(
        host="127.0.0.1",
        port=6379,
        database="sever_test_memory_checkpoints",
    )
    flow = build_flow(live_port, checkpointer=saver)
    pending = start_investigation(flow, Finding("F-9", "credential_breach", HERO), "case-DB")
    assert pending["proposal"]
    flow2 = build_flow(live_port, checkpointer=saver)
    result = resume_investigation(flow2, "case-DB", approve=True, approved_by="saver-test")
    assert result["receipt"]["verdict"] == "collapsed"
    assert live_port.reachability() == 0


def test_case_log_append_and_read(tmp_path):
    log = CaseLog("sever_demo", root=tmp_path)
    log.append({"step": "triaged", "finding": "F-1"})
    log.append({"step": "verified", "cut": "x"})
    events = log.read()
    assert [e["step"] for e in events] == ["triaged", "verified"]
    assert events[0]["ts"]
    assert log.last_step() == "verified"
