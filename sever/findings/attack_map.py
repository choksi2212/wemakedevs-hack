"""ATT&CK narration map — finding kinds -> technique + spoken narrative.

CVE->ATT&CK mapping feasibility is grounded in published results
(macro-F1 87.71% techniques / 96.16% tactics, arXiv:2606.31557); SEVER's
narratives are deterministic templates so the demo never depends on
LLM availability for its load-bearing moments.
"""
from __future__ import annotations

from dataclasses import dataclass

from sever.findings.stream import Finding


@dataclass(frozen=True)
class AttackNarrative:
    technique_id: str
    technique: str
    narration: str


ATTACK_MAP: dict[str, AttackNarrative] = {
    "credential_breach": AttackNarrative(
        "T1078.002",
        "Valid Accounts: Domain Accounts",
        "Compromised domain credentials confirmed. This principal is now assumed controlled by the attacker — every path it can reach is in scope.",
    ),
    "kerberoastable_spn": AttackNarrative(
        "T1558.003",
        "Steal or Forge Authentication Tickets: Kerberoasting",
        "A service principal name is exposed on this principal. An attacker can request a service ticket offline and crack it at leisure.",
    ),
    "ace_granted": AttackNarrative(
        "T1098",
        "Account Manipulation",
        "An excessive access control right was just granted. The identity graph now carries a new abusable edge — re-scoring all attack paths.",
    ),
    "dcsync_right": AttackNarrative(
        "T1003.002",
        "OS Credential Dumping: DCSync",
        "Directory replication rights detected. Whoever holds them can impersonate the domain controller and harvest every credential hash.",
    ),
    "cross_domain_trust": AttackNarrative(
        "T1482",
        "Domain Trust Discovery",
        "A path crosses a domain trust. Compromise in one domain now cascades into another forest's crown jewels.",
    ),
    "cert_esc1": AttackNarrative(
        "T1649",
        "Steal or Forge Authentication Certificates",
        "A misconfigured certificate template allows enrollee-supplied subjects. An attacker can mint a certificate as ANY identity, including administrators.",
    ),
}


def narrate(finding: Finding) -> AttackNarrative:
    return ATTACK_MAP.get(
        finding.kind,
        AttackNarrative("T1595.002", "Active Scanning: Vulnerability Scanning", finding.detail or "Finding flagged."),
    )
