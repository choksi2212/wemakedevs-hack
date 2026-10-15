"""Flow-gate contract + case ledger — DB-free.

The full start/resume pipeline (triage -> propose -> gate -> verify) executes
Cypher and needs the REAL engine; those tests live in test_memory.py. This
module pins the seams that must hold with no engine at all:

- resume_investigation rejects every approval value that is not the exact
  bool True/False — BEFORE any flow or checkpointer interaction (same
  contract as Investigator.approve_and_cut), and refuses to resume a
  thread that is not paused at the gate;
- verify_node's exact-True gate is DB-free via a scripted port: the full
  pipeline runs on an in-memory estate, so a truthy stand-in, a missing
  proposal and the approved execution path are pinned without FalkorDB
  (plus the live pin in test_memory.py);
- double-resume on a completed thread is fail-closed: it raises BEFORE any
  state mutation, so the cut can never re-execute (fleet-2 rule, re-verified
  post-merges);
- interleaved threads on one checkpointer stay isolated (the DB-free mirror
  of the live isolation beat);
- CaseLog (the receipts trail) round-trips JSON on disk, including the
  empty-file / missing-file / blank-line edges, and is safe under TWO
  CONCURRENT APPENDING PROCESSES — every line valid JSON, no interleaved
  partials (regression pin for the locked append; the unlocked append lost
  ~5-13% of events on Windows).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sever.findings.stream import Finding
from sever.memory.flow import (
    CaseLog,
    build_flow,
    resume_investigation,
    start_investigation,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]

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


# verify_node's exact-True state check is pinned BOTH ways:
# - DB-free with a scripted in-memory estate below (the full pipeline runs
#   without FalkorDB, so every gate branch is testable offline), and
# - live on the engine in test_memory.py::test_flow_state_gate_requires_exact_true.


class TripwirePort:
    """A port that fails the test if the flow touches ANY engine method —
    proves the gate-closed paths never reach the estate."""

    def __getattr__(self, name: str):
        raise AssertionError(f"engine touched through gate-closed path: {name}")


class ScriptedFlowPort:
    """Full GraphPort duck-type over an in-memory estate, so the whole
    triage -> propose -> gate -> verify pipeline runs with NO engine.

    Estate: one compromised principal (marked owned by triage) reaches the
    single jewel through S-a -MEMBER_OF-> S-b -MEMBER_OF-> S-jewel, so the
    ranked proposal top is always (S-a, MEMBER_OF, S-b). Reachability is
    computed live from the remaining edges: once the first hop is cut the
    case collapses — and a second thread resuming the SAME stored proposal
    gets an honest no_effect receipt (stale proposal on a mutated shared
    estate)."""

    def __init__(self):
        self.owned: set[str] = set()
        self.cut_calls: list[tuple[str, str, str]] = []
        self.intact_edges: list[tuple[str, str, str]] = [
            ("S-a", "S-b", "MEMBER_OF"), ("S-b", "S-jewel", "MEMBER_OF"),
        ]

    def reachability(self, hop_cap: int | None = None) -> int:
        return 1 if ("S-a", "S-b", "MEMBER_OF") in self.intact_edges else 0

    def owned_ids(self) -> list[str]:
        return sorted(self.owned)

    def crown_jewels(self) -> list[str]:
        return ["S-jewel"]

    def node_count(self) -> int:
        return 3

    def edge_count(self) -> int:
        return 2

    def mark_owned(self, oid: str) -> None:
        self.owned.add(oid)

    def paths_to_jewels(self, oid: str, hop_cap: int | None = None, ties: bool = False):
        if oid not in self.owned or ("S-a", "S-b", "MEMBER_OF") not in self.intact_edges:
            return []
        return [[("S-a", "MEMBER_OF", "S-b"), ("S-b", "MEMBER_OF", "S-jewel")]]

    def edge_frequency(self, hop_cap: int | None = None) -> dict[tuple[str, str, str], int]:
        freq: dict[tuple[str, str, str], int] = {}
        for owned in self.owned_ids():
            for path in self.paths_to_jewels(owned, hop_cap):
                for hop in path:
                    freq[hop] = freq.get(hop, 0) + 1
        return freq

    def cut(self, src: str, dst: str, rel: str) -> int:
        self.cut_calls.append((src, dst, rel))
        if (src, dst, rel) in self.intact_edges:
            self.intact_edges.remove((src, dst, rel))
            return 1
        return 0  # edge already gone: idempotent, honestly reported


def _memory_saver():
    pytest.importorskip("langgraph")
    from langgraph.checkpoint.memory import MemorySaver

    return MemorySaver()


def _paused_flow(port, thread: str, finding_id: str = "F-1", subject: str = "S-a"):
    """Run the REAL pipeline DB-free up to the human gate."""
    flow = build_flow(port=port, checkpointer=_memory_saver())
    pending = start_investigation(flow, Finding(finding_id, "credential_breach", subject), thread)
    return flow, pending


# ---- verify_node: the exact-True gate, DB-free (fleet-2 rule 1) ----


@pytest.mark.parametrize(
    "standin",
    ["yes", "true", "True", 1, 1.0, [True], {"approved": True}, (True,), "on"],
    ids=repr,
)
def test_verify_node_truthy_standin_closes_gate_dbfree(standin):
    """A truthy stand-in recorded straight into the thread state must close
    the gate — and the engine must never be touched on the way down. The
    thread is seeded as if it had paused at the gate (update_state with
    as_node='gate', the same mechanism the live interrupt produces), so the
    ONLY code that can run is verify_node and the tripwire port proves it
    never reaches the estate."""
    flow = build_flow(port=TripwirePort(), checkpointer=_memory_saver())
    config = {"configurable": {"thread_id": "case-standin"}}
    flow.update_state(config, {
        "finding_id": "F-1", "finding_kind": "credential_breach", "subject": "S-a",
        "triage": {"finding": "F-1"}, "proposal": [
            {"src": "S-a", "rel": "MEMBER_OF", "dst": "S-b", "paths_on": 1},
        ],
        "step": "awaiting_approval",
        "approved": standin,  # truthy, but NOT the bool True
    }, as_node="gate")
    flow.invoke(None, config=config)
    result = flow.get_state(config).values
    assert result["step"] == "gate_closed"
    assert "receipt" not in result  # nothing executed, engine never touched


def test_verify_node_missing_proposal_closes_gate_dbfree():
    """Approved exactly True but no proposal: verify has nothing to execute —
    the gate stays closed and the engine is never touched."""
    flow = build_flow(port=TripwirePort(), checkpointer=_memory_saver())
    config = {"configurable": {"thread_id": "case-noprop"}}
    # seed the thread as if it had paused at the gate with an empty proposal
    flow.update_state(config, {
        "finding_id": "F-1", "finding_kind": "credential_breach", "subject": "S-a",
        "triage": {"finding": "F-1"}, "proposal": [], "step": "awaiting_approval",
        "approved": True,
    }, as_node="gate")
    flow.invoke(None, config=config)
    result = flow.get_state(config).values
    assert result["step"] == "gate_closed"
    assert "receipt" not in result


def test_verify_node_exact_true_executes_the_stored_proposal_dbfree():
    """The full DB-free pipeline: approval of exactly True executes the STORED
    top proposal (never a recomputed one) and records the receipt."""
    port = ScriptedFlowPort()
    flow, pending = _paused_flow(port, "case-exec", finding_id="F-1")
    top = pending["proposal"][0]
    result = resume_investigation(flow, "case-exec", approve=True, approved_by="manas")
    assert result["step"] == "verified"
    assert port.cut_calls == [(top["src"], top["dst"], top["rel"])]
    assert result["receipt"]["cut"]["src"] == top["src"]
    assert result["receipt"]["verdict"] == "collapsed"
    assert result["receipt"]["approved_by"] == "manas"


def test_resume_close_without_approval_cuts_nothing_dbfree():
    port = ScriptedFlowPort()
    flow, _ = _paused_flow(port, "case-close")
    result = resume_investigation(flow, "case-close", approve=False)
    assert result["step"] == "gate_closed"
    assert "receipt" not in result
    assert port.cut_calls == []  # no mutation without a human yes


# ---- double-resume on a completed thread: fail-closed no-op (fleet-2 rule 3) ----


def test_double_resume_is_fail_closed_and_reexecutes_nothing_dbfree():
    """A completed thread is not paused at the gate, so the second resume
    raises BEFORE update_state — the cut cannot re-execute and the recorded
    approval is not overwritten."""
    port = ScriptedFlowPort()
    flow, _ = _paused_flow(port, "case-once")
    first = resume_investigation(flow, "case-once", approve=True, approved_by="day-shift")
    assert first["step"] == "verified"

    with pytest.raises(ValueError, match="not paused at the gate"):
        resume_investigation(flow, "case-once", approve=True, approved_by="evil-twin")

    assert port.cut_calls and len(port.cut_calls) == 1  # exactly one cut, ever
    state = flow.get_state({"configurable": {"thread_id": "case-once"}}).values
    assert state["receipt"]["approved_by"] == "day-shift"  # not overwritten


# ---- interleaved threads on one checkpointer: state isolation (DB-free mirror) ----


def test_interleaved_threads_never_cross_contaminate_dbfree():
    """start A, start B, resume A, resume B on ONE checkpointer: each resume
    remembers its OWN finding/subject/proposal — the live beat's mirror."""
    from langgraph.checkpoint.memory import MemorySaver

    port = ScriptedFlowPort()
    checkpointer = MemorySaver()  # one shared checkpointer, two flow objects
    flow_a = build_flow(port=port, checkpointer=checkpointer)
    flow_b = build_flow(port=port, checkpointer=checkpointer)

    pending_a = start_investigation(flow_a, Finding("F-A", "credential_breach", "S-a"), "case-A")
    pending_b = start_investigation(flow_b, Finding("F-B", "credential_breach", "S-b"), "case-B")
    assert pending_a["triage"]["finding"] == "F-A"
    assert pending_b["triage"]["finding"] == "F-B"

    # resume through FRESH flow objects, interleaved in the mandated order
    resumed_a = resume_investigation(
        build_flow(port=port, checkpointer=checkpointer), "case-A", approve=True, approved_by="op-A")
    resumed_b = resume_investigation(
        build_flow(port=port, checkpointer=checkpointer), "case-B", approve=True, approved_by="op-B")

    for resumed, pending, fid in ((resumed_a, pending_a, "F-A"), (resumed_b, pending_b, "F-B")):
        assert resumed["triage"]["finding"] == fid  # remembered ITS OWN finding
        assert resumed["proposal"] == pending["proposal"]  # ITS OWN stored proposal
    assert resumed_a["receipt"]["approved_by"] == "op-A"
    assert resumed_b["receipt"]["approved_by"] == "op-B"
    # thread A's stored top proposal collapses the shared estate...
    assert resumed_a["receipt"]["verdict"] == "collapsed"
    # ...and thread B then replays ITS OWN stored proposal against the already-
    # mutated estate: the cut is idempotent (removes 0) and the receipt says
    # no_effect — honest shared-world semantics, NEVER a wrong-state resume.
    assert resumed_b["receipt"]["verdict"] == "no_effect"
    assert resumed_b["receipt"]["cut"]["relationships_removed"] == 0
    # each thread executed its own stored top proposal, in order
    assert port.cut_calls == [
        (pending_a["proposal"][0]["src"], pending_a["proposal"][0]["dst"], pending_a["proposal"][0]["rel"]),
        (pending_b["proposal"][0]["src"], pending_b["proposal"][0]["dst"], pending_b["proposal"][0]["rel"]),
    ]


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


# ---- CaseLog under concurrent PROCESSES (not threads) ----

_CASELOG_WORKER = """
import sys
sys.path.insert(0, sys.argv[1])
from sever.memory.flow import CaseLog

tenant, root, worker, count, pad_bytes = (
    sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
)
log = CaseLog(tenant, root=root)
pad = "x" * pad_bytes
for i in range(count):
    log.append({"step": "stress", "worker": worker, "i": i, "pad": pad})
"""


def test_caselog_two_processes_concurrent_append_no_interleaved_partials(tmp_path):
    """TWO REAL PROCESSES appending concurrently (the two-console-instance
    deployment shape): every line must be complete valid JSON, every event
    must survive, and no two events may share a line. Regression pin for the
    locked append — the unlocked append lost ~5-13% of events and minted
    partial lines on Windows (measured 2x300x8KB and 2x400x0KB)."""
    worker_script = tmp_path / "caselog_worker.py"
    worker_script.write_text(_CASELOG_WORKER, encoding="ascii")

    per_worker, pad_bytes = 150, 2048
    procs = [
        subprocess.Popen(
            [sys.executable, str(worker_script), str(_REPO_ROOT), "sever_stress",
             str(tmp_path), worker, str(per_worker), str(pad_bytes)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for worker in ("A", "B")
    ]
    for p in procs:
        _, err = p.communicate(timeout=180)
        assert p.returncode == 0, f"worker failed: {err[-400:]}"

    ledger = tmp_path / "sever_stress.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 * per_worker  # zero lost, zero duplicated

    seen = {"A": 0, "B": 0}
    for line in lines:
        event = json.loads(line)  # raises on any interleaved partial line
        assert event["step"] == "stress"
        assert len(event["pad"]) == pad_bytes  # payload intact, not truncated
        seen[event["worker"]] += 1
    assert seen == {"A": per_worker, "B": per_worker}
