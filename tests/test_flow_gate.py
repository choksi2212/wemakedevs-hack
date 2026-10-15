"""Flow-gate contract + case ledger — DB-free.

The full start/resume pipeline (triage -> propose -> gate -> verify) executes
Cypher and needs the REAL engine; those tests live in test_memory.py. This
module pins the seams that must hold with no engine at all:

- resume_investigation rejects every approval value that is not the exact
  bool True/False — BEFORE any flow or checkpointer interaction (same
  contract as Investigator.approve_and_cut), and refuses to resume a
  thread that is not paused at the gate;
- CaseLog (the receipts trail) round-trips JSON on disk, including the
  empty-file / missing-file / blank-line edges.
"""
from __future__ import annotations

import pytest

from sever.findings.stream import Finding
from sever.memory.flow import CaseLog, build_flow, resume_investigation

# ---- resume_investigation: the gate value contract (DB-free) ----

# None of these are the bool True; all must raise before anything runs.
NON_BOOL_APPROVALS = [
    None,
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


@pytest.mark.parametrize("bad", NON_BOOL_APPROVALS, ids=repr)
def test_resume_rejects_non_bool_approval(bad):
    # object() as the flow: the ValueError fires BEFORE any flow interaction,
    # so no engine, no checkpointer, no langgraph graph is ever touched.
    with pytest.raises(ValueError, match="explicit human approval"):
        resume_investigation(object(), "case-X", approve=bad)


def test_resume_on_thread_not_paused_at_gate_raises():
    """A resume can never mint a new investigation: without this guard
    LangGraph's invoke(None) on a fresh/finished thread runs the graph from
    the START node (verified on langgraph 1.2.15). The engine is never
    touched here — the guard raises before any node could run."""
    pytest.importorskip("langgraph")
    from langgraph.checkpoint.memory import MemorySaver

    flow = build_flow(port=None, checkpointer=MemorySaver())
    for approve in (True, False):
        with pytest.raises(ValueError, match="not paused at the gate"):
            resume_investigation(flow, "never-started-thread", approve=approve)


# verify_node's exact-True state check (a truthy "yes" recorded in the thread
# state must close the gate) runs the full pipeline, so it is pinned on the
# REAL engine in test_memory.py::test_flow_state_gate_requires_exact_true.


# ---- CaseLog: the receipts trail (DB-free) ----


def test_caselog_read_on_missing_file_is_empty(tmp_path):
    log = CaseLog("sever_missing", root=tmp_path)
    assert log.read() == []
    assert log.last_step() is None


def test_caselog_read_on_empty_file_is_empty(tmp_path):
    log = CaseLog("sever_empty", root=tmp_path)
    log.path.touch()
    assert log.read() == []
    assert log.last_step() is None
    # appending after an empty ledger still works
    log.append({"step": "triaged", "finding": "F-1"})
    assert [e["step"] for e in log.read()] == ["triaged"]
    assert log.last_step() == "triaged"


def test_caselog_read_skips_blank_lines(tmp_path):
    log = CaseLog("sever_blank", root=tmp_path)
    log.append({"step": "a"})
    with log.path.open("a", encoding="utf-8") as f:
        f.write("\n   \n")  # external tampering / partial write
    log.append({"step": "b"})
    assert [e["step"] for e in log.read()] == ["a", "b"]


def test_caselog_round_trips_concrete_and_cut_receipts(tmp_path):
    """The two shapes the console actually records — a finding/triage event
    and a cut receipt — survive the JSONL ledger byte-for-byte."""
    log = CaseLog("sever_demo", root=tmp_path)
    log.append({"step": "finding", "finding": "F-ab12", "kind": "credential_breach", "triage": {
        "finding": "F-ab12", "kind": "credential_breach", "applied": False,
        "before": {"reachability": 1, "owned": [], "jewels": ["S-1-5-21-t-t-512"], "nodes": 1480, "edges": 3112},
        "after": {"reachability": 1, "owned": ["S-1"], "jewels": ["S-1-5-21-t-t-512"], "nodes": 1480, "edges": 3112},
        "technique": "T1078.002 Valid Accounts: Domain Accounts",
        "narration": "Compromised domain credentials confirmed.",
        "paths": 0, "proposal": [],
    }})
    log.append({"step": "cut", "receipt": {
        "cut": {"src": "S-1", "dst": "S-2", "rel": "GENERIC_ALL", "relationships_removed": 1},
        "before": {"reachability": 1}, "after": {"reachability": 0},
        "requery_ms": 0.83, "verdict": "collapsed",
        "approved_by": "console-operator", "approved_at": "2026-10-15T15:00:00",
    }})
    events = log.read()
    assert [e["step"] for e in events] == ["finding", "cut"]
    assert all(e["ts"] for e in events)
    assert events[1]["receipt"]["verdict"] == "collapsed"
    assert log.last_step() == "cut"


def test_caselog_namespaces_per_tenant(tmp_path):
    a = CaseLog("tenant-a", root=tmp_path)
    b = CaseLog("tenant-b", root=tmp_path)
    a.append({"step": "state"})
    assert b.read() == []  # separate ledgers, no cross-tenant bleed
