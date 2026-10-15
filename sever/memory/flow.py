"""Resumable investigation flow — SEVER's Track-2 story: agents that remember.

The investigation pipeline runs as a LangGraph StateGraph with a checkpointer
and an INTERRUPT before the verify step — the human gate is structural:

    triage -> propose -> gate -> [INTERRUPT: operator inspects the proposal]
                                -> verify (executes the approved cut) -> end

- every step's state is persisted (episodic case memory),
- an interrupted run resumes exactly where it stopped: kill the process
  mid-investigation, start a fresh one on the same thread id, and it picks
  up with zero re-explanation (the "night-shift handoff" beat),
- on the live deployment the checkpointer is FalkorDBSaver — case memory
  lives IN the graph database, shared across processes and agents
  (langchain-falkordb 0.2.0); offline/tests use LangGraph's MemorySaver.

Resuming never bypasses the gate: the cut only executes when the operator
explicitly records the exact value ``True`` into the thread state —
``resume_investigation`` rejects every other value, and ``verify_node``
re-checks the state itself, so no truthy stand-in ("yes", 1, a dict) can
ever reach ``approve_and_cut`` through the flow.
"""
from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, TypedDict

if sys.platform == "win32":
    import time as _time

    import msvcrt

    def _lock_handle(f: Any) -> None:
        # Spin on the non-blocking lock: msvcrt's blocking LK_LOCK retries at
        # ~1s granularity, which makes contended handoff ~100x slower than
        # needed. A crashed holder cannot wedge the ledger — Windows owns
        # these locks and releases them when the process dies.
        f.seek(0)
        deadline = _time.monotonic() + 60.0
        while True:
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if _time.monotonic() > deadline:
                    raise RuntimeError("CaseLog ledger lock is wedged (>60s)") from None
                _time.sleep(0.002)

    def _unlock_handle(f: Any) -> None:
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
else:  # POSIX
    import fcntl

    def _lock_handle(f: Any) -> None:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

    def _unlock_handle(f: Any) -> None:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph

from sever.agent.investigator import Investigator
from sever.core.port import GraphPort
from sever.findings.stream import Finding


class InvestigationState(TypedDict, total=False):
    finding_id: str
    finding_kind: str
    subject: str
    triage: dict[str, Any]
    proposal: list[dict[str, Any]]
    approved: bool
    approved_by: str
    receipt: dict[str, Any]
    step: str


def build_flow(
    port: GraphPort,
    llm: Any = None,
    checkpointer: BaseCheckpointSaver | None = None,
    interrupt_at_gate: bool = True,
) -> Any:
    """Assemble the investigation graph. The checkpointer makes it resumable;
    ``FalkorDBSaver`` on live deployments, ``MemorySaver`` offline."""
    inv = Investigator(port, llm=llm)

    def triage_node(state: InvestigationState) -> InvestigationState:
        finding = Finding(
            id=state["finding_id"], kind=state["finding_kind"], subject=state["subject"]
        )
        report = inv.triage(finding)
        return {**state, "triage": report.as_dict(), "step": "triaged"}

    def propose_node(state: InvestigationState) -> InvestigationState:
        return {**state, "proposal": inv.propose(limit=3), "step": "proposed"}

    def gate_node(state: InvestigationState) -> InvestigationState:
        return {**state, "step": "awaiting_approval"}

    def verify_node(state: InvestigationState) -> InvestigationState:
        # The flow's gate is exactly as strict as the investigator's: only the
        # bool True recorded in the thread state is an approval. A truthy
        # stand-in ("yes", 1, {"approved": True}) closes the gate — fail closed.
        if state.get("approved") is not True or not state.get("proposal"):
            return {**state, "step": "gate_closed"}
        top = state["proposal"][0]
        receipt = inv.approve_and_cut(
            top["src"], top["dst"], top["rel"], approved_by=state.get("approved_by", "on-call-analyst")
        )
        return {**state, "receipt": receipt, "step": "verified"}

    g = StateGraph(InvestigationState)
    g.add_node("triage", triage_node)
    g.add_node("propose", propose_node)
    g.add_node("gate", gate_node)
    g.add_node("verify", verify_node)
    g.add_edge(START, "triage")
    g.add_edge("triage", "propose")
    g.add_edge("propose", "gate")
    g.add_edge("gate", "verify")
    g.add_edge("verify", END)
    return g.compile(
        checkpointer=checkpointer,
        interrupt_before=["verify"] if interrupt_at_gate else None,
    )


def start_investigation(flow: Any, finding: Finding, thread_id: str) -> dict[str, Any]:
    """Run up to the human gate and pause. Returns the pending state
    (with the ranked proposal) for the operator to inspect."""
    config = {"configurable": {"thread_id": thread_id}}
    state: dict[str, Any] = {
        "finding_id": finding.id,
        "finding_kind": finding.kind,
        "subject": finding.subject,
    }
    flow.invoke(state, config=config)
    return flow.get_state(config).values


def resume_investigation(
    flow: Any,
    thread_id: str,
    approve: bool,
    approved_by: str = "on-call-analyst",
) -> dict[str, Any]:
    """Resume a paused investigation. ``approve=True`` records the human
    decision into the thread state and continues; ``approve=False`` closes
    the gate with no mutation. Works from a FRESH process if the
    checkpointer is shared (MemorySaver in-process, FalkorDBSaver live).

    Gate integrity, same contract as ``Investigator.approve_and_cut``:
    only the bool ``True`` is an approval — any other value raises, so a
    truthy stand-in can never slip into the thread state. Resuming a
    thread that is not paused at the gate raises too: without the guard
    ``invoke(None)`` on a fresh thread would run the graph from the START
    node (a resume can never mint a new investigation).
    """
    config = {"configurable": {"thread_id": thread_id}}
    if approve is not True and approve is not False:
        raise ValueError("interdiction requires explicit human approval")
    if "verify" not in flow.get_state(config).next:
        raise ValueError(f"thread {thread_id!r} is not paused at the gate")
    if approve:
        flow.update_state(config, {"approved": True, "approved_by": approved_by})
    else:
        flow.update_state(config, {"approved": False})
    flow.invoke(None, config=config)
    return flow.get_state(config).values


class CaseLog:
    """Append-only case ledger per tenant — the receipts trail (JSONL).

    Multi-PROCESS safe: several operator processes share one tenant ledger
    (concurrent console instances, resume drivers), and the naive append-mode
    write is not atomic across processes — on Windows the CRT's O_APPEND
    emulation is seek-then-write with no interlock and on POSIX any line
    larger than the stdio buffer splits across write() calls. Measured on
    the Windows substrate with the unlocked append: two concurrent writers
    lost ~5-13% of events and minted unparseable partial lines. Every
    append therefore holds an exclusive lock on a sidecar lock file, and
    read() takes the same lock so a reader can never observe a torn line.
    """

    def __init__(self, tenant: str, root: str | Path = "out/cases") -> None:
        self.path = Path(root) / f"{tenant}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.parent / (self.path.name + ".lock")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._lock_path.open("a+b") as lockf:
            _lock_handle(lockf)
            try:
                yield
            finally:
                _unlock_handle(lockf)

    def append(self, event: dict[str, Any]) -> None:
        event = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **event}
        line = json.dumps(event, default=str) + "\n"
        with self._locked():
            # a previous writer may have died mid-line: terminate the torn
            # fragment and stamp a repair record so it can never merge with
            # this line and read() can skip it (audit3/console-logic contract)
            if self.path.exists() and self.path.stat().st_size:
                with self.path.open("rb") as probe:
                    probe.seek(-1, os.SEEK_END)
                    if probe.read(1) != b"\n":
                        line = (
                            "\n"
                            + json.dumps({
                                "step": "ledger_repair",
                                "note": "terminated a torn trailing fragment left by a crashed writer",
                            }, default=str)
                            + "\n"
                            + line
                        )
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self._locked():
            raw = self.path.read_text(encoding="utf-8")
        lines = raw.split("\n")
        torn_tail: str | None = None
        if lines and lines[-1] == "":
            lines.pop()
        elif lines:
            torn_tail = lines.pop()
        events: list[dict[str, Any]] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            try:
                events.append(json.loads(line))
                i += 1
            except json.JSONDecodeError:
                # a broken line is tolerated ONLY when the very next line is
                # a repair record (i.e. it was a torn tail that append()
                # terminated) — anything else is genuine mid-file corruption
                # and must surface loudly, never hide.
                nxt = lines[i + 1] if i + 1 < len(lines) else ""
                try:
                    repaired = json.loads(nxt).get("step") == "ledger_repair"
                except Exception:
                    repaired = False
                if not repaired:
                    raise RuntimeError(
                        f"{self.path}: corrupt ledger line {i + 1}: {line[:120]!r}"
                    ) from None
                events.append(json.loads(nxt))  # the repair record stays visible
                i += 2  # skip the repaired fragment + consume the repair record
        if torn_tail is not None and torn_tail.strip():
            # the writer died mid-line before the trailing newline: tolerate
            # and DROP the fragment (it can never merge with a later line —
            # the next append terminates it with a visible repair record)
            # instead of 500ing every future read.
            try:
                events.append(json.loads(torn_tail))
            except json.JSONDecodeError:
                pass
        return events

    def last_step(self) -> str | None:
        events = self.read()
        return events[-1].get("step") if events else None
