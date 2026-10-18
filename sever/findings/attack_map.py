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
        "Compromised domain credentials flagged. This principal is now assumed controlled by the attacker — every path it can reach is in scope.",
    ),
    "kerberoastable_spn": AttackNarrative(
        "T1558.003",
        "Steal or Forge Kerberos Tickets: Kerberoasting",
        "A service principal name is exposed on this principal. An attacker with a valid ticket-granting ticket can request its service ticket from the domain controller and crack it offline at leisure.",
    ),
    "ace_granted": AttackNarrative(
        "T1098",
        "Account Manipulation",
        "An excessive access control right was just granted. The identity graph now carries a new abusable edge — re-scoring all attack paths.",
    ),
    "dcsync_right": AttackNarrative(
        "T1003.006",
        "OS Credential Dumping: DCSync",
        "Directory replication rights detected. Whoever holds them can impersonate the domain controller and harvest every credential hash.",
    ),
    "cross_domain_trust": AttackNarrative(
        "T1482",
        "Domain Trust Discovery",
        "Trust-discovery surface flagged: a traversable domain-trust path "
        "exists. Principals in one domain can enumerate this trust "
        "relationship and follow it into the trusted domain's crown jewels — "
        "the exposure is the trust itself, not an exploit.",
    ),
    "cert_esc1": AttackNarrative(
        "T1649",
        "Steal or Forge Authentication Certificates",
        "A misconfigured certificate template allows enrollee-supplied subjects. An attacker with enrollment rights can mint a certificate as any identity, including administrators.",
    ),
}


def narrate(finding: Finding) -> AttackNarrative:
    """Narrate a finding. Unknown kinds get a kind-NEUTRAL fallback — never
    a fabricated ATT&CK label (owner resolution #4, audit M69): the HTTP
    schema layer already 422s unknown kinds (schemas.py documents the
    pre-fix 'T1595.002' fallback as the fabrication bug), and this path is
    the backstop for any non-HTTP caller (scripts, library use, a
    hand-built Finding) — it names the kind and admits the mapping gap."""
    return ATTACK_MAP.get(
        finding.kind,
        AttackNarrative(
            "UNMAPPED",
            "Unmapped finding kind",
            f"Finding of kind {finding.kind!r} flagged — no ATT&CK technique "
            "is mapped for this kind, and SEVER never fabricates one.",
        ),
    )
