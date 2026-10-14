"""Synthetic security-findings stream — the live input SEVER reacts to.

The stream is deterministic (replay-identical) and graph-mutating: each finding
can carry an ``apply`` edge grant, so the attack surface changes in front of the
audience. Public/synthetic data only (hackathon rule 6); the demo presents it as
a labeled "breach-timeline replay" of the disclosed simulated environment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sever.core.port import GraphPort


@dataclass(frozen=True)
class Finding:
    id: str
    kind: str
    subject: str                 # principal the finding is about
    target: str | None = None    # optional second endpoint
    rel: str | None = None       # edge type when the finding grants one
    detail: str = ""
    grants_edge: bool = False    # True -> apply() adds rel: subject->target


def apply_finding(port: GraphPort, finding: Finding) -> bool:
    """Mutate the graph if the finding grants an edge. Idempotent."""
    if finding.grants_edge and finding.target and finding.rel:
        return port.add_edge(finding.subject, finding.target, finding.rel, {"source": finding.id})
    return False


def default_timeline(hero: str, ace_target: str, jewel: str) -> list[Finding]:
    """Deterministic demo timeline for the hero tenant.

    Order matters: the FIRST finding turns the hero principal 'owned'
    (breach entry), F-002..N escalate / mutate the surface live.
    All ids are REAL objectids resolved from the loaded tenant graph.
    """
    return [
        Finding(
            id="F-001",
            kind="credential_breach",
            subject=hero,
            detail="Infostealer credential dump flagged: principal is COMPROMISED. Marking owned.",
        ),
        Finding(
            id="F-002",
            kind="kerberoastable_spn",
            subject=hero,
            detail="SPN visible on compromised principal — offline kerberoast surface.",
        ),
        Finding(
            id="F-003",
            kind="ace_granted",
            subject=hero,
            target=ace_target,
            rel="GENERIC_ALL",
            grants_edge=True,
            detail="Excessive ACE: GenericAll granted on tier-1 resource. Graph mutated live.",
        ),
        Finding(
            id="F-004",
            kind="cross_domain_trust",
            subject=hero,
            target=jewel,
            detail="Cross-domain path flagged via domain trust.",
        ),
    ]


class FindingStream:
    """Replay-identical stream; the agent consumes one finding at a time."""

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = list(findings)
        self._i = 0

    def __iter__(self) -> "FindingStream":
        return self

    def __next__(self) -> Finding:
        if self._i >= len(self._findings):
            raise StopIteration
        f = self._findings[self._i]
        self._i += 1
        return f

    def remaining(self) -> int:
        return len(self._findings) - self._i
