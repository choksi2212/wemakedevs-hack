"""Investigator — the agent loop that turns findings into gated interdictions.

Anti-agent-washing stance: the LLM narrates; Cypher and the scoring engine do
the work; a HUMAN approves the cut. SEVER never mutates the environment without
an explicit approval — the same design constraint the security industry itself
chooses (SpecterOps keeps its agentic Hunter read-only).

Flow: finding -> apply -> measure -> narrate -> PROPOSE -> [human] -> interdict
      -> re-verify -> receipt.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sever.agent.llm import LLM, NullLLM
from sever.core.jewels import DEFAULT_HOP_CAP
from sever.core.port import GraphPort
from sever.core.scoring import interdict, rank_cut_candidates, snapshot
from sever.findings.attack_map import narrate
from sever.findings.stream import Finding, apply_finding

NARRATE_SYSTEM = (
    "You are SEVER, an on-call identity-security agent. You explain attack paths "
    "concisely in plain language. You never recommend autonomous changes — you "
    "propose a single ranked remediation and wait for human approval."
)


@dataclass
class TriageReport:
    finding: Finding
    applied: bool
    before: dict[str, Any]
    after: dict[str, Any]
    narration_technique: str
    narration: str
    paths_for_subject: list[list[tuple[str, str, str]]]
    proposal: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding.id,
            "kind": self.finding.kind,
            "applied": self.applied,
            "before": self.before,
            "after": self.after,
            "technique": self.narration_technique,
            "narration": self.narration,
            "paths": len(self.paths_for_subject),
            "proposal": self.proposal,
        }


class Investigator:
    def __init__(self, port: GraphPort, llm: LLM | None = None, hop_cap: int = DEFAULT_HOP_CAP) -> None:
        self.port = port
        self.llm = llm or NullLLM()
        self.hop_cap = hop_cap
        self.case_log: list[dict[str, Any]] = []

    # ---- triage ----
    def triage(self, finding: Finding) -> TriageReport:
        before = snapshot(self.port, self.hop_cap)
        applied = apply_finding(self.port, finding)
        if finding.kind == "credential_breach":
            self.port.mark_owned(finding.subject)
        after = snapshot(self.port, self.hop_cap)
        paths = self.port.paths_to_jewels(finding.subject, self.hop_cap) if after["owned"] else []
        story = narrate(finding)
        garnish = self.llm.complete(
            NARRATE_SYSTEM,
            f"Finding: {finding.detail or finding.kind} on {finding.subject}. "
            f"Graph context: {len(paths)} paths to crown jewels after this finding. "
            f"One-line commentary for the on-call analyst:",
        ).strip()
        proposal = rank_cut_candidates(self.port.edge_frequency(self.hop_cap), limit=3) if paths else []
        report = TriageReport(
            finding=finding,
            applied=applied,
            before=before,
            after=after,
            narration_technique=f"{story.technique_id} {story.technique}",
            narration=(f"{story.narration}" + (f" {garnish}" if garnish else "")),
            paths_for_subject=paths,
            proposal=proposal,
        )
        self.case_log.append(report.as_dict())
        return report

    # ---- human gate ----
    def propose(self, limit: int = 3) -> list[dict[str, Any]]:
        return rank_cut_candidates(self.port.edge_frequency(self.hop_cap), limit=limit)

    def approve_and_cut(
        self,
        src: str,
        dst: str,
        rel: str,
        approved_by: str = "on-call-analyst",
        require_explicit_approval: object = True,
    ) -> dict[str, Any]:
        """THE ONLY path to mutation. The gate passes on the exact value ``True``
        — nothing else — so callers cannot slip a truthy value through."""
        if require_explicit_approval is not True:
            raise ValueError("interdiction requires explicit human approval")
        receipt = interdict(self.port, src, dst, rel, self.hop_cap)
        receipt["approved_by"] = approved_by
        receipt["approved_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.case_log.append({"cut": receipt})
        return receipt
