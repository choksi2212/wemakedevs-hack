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
import time
from pathlib import Path
from typing import Any, TypedDict

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
    """Append-only case ledger per tenant — the receipts trail (JSONL)."""

    def __init__(self, tenant: str, root: str | Path = "out/cases") -> None:
        self.path = Path(root) / f"{tenant}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: dict[str, Any]) -> None:
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def last_step(self) -> str | None:
        events = self.read()
        return events[-1].get("step") if events else None
