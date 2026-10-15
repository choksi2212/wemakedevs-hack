"""Console request-schema validation — engine-free (audit/security).

Proves CutRequest / FindingRequest reject absurd input sizes and Cypher
injection payloads at the pydantic layer, so FastAPI answers 422 before any
query template is touched. No engine, no FastAPI — just the models.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from sever.console.schemas import CutRequest, FindingRequest

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"

INJECTION_RELS = [
    "MEMBER_OF}]->(t) DETACH DELETE n //",
    "MEMBER_OF` RETURN 1 //",
    "MEMBER_OF:1",
    "MEMBER_OF x",
    "member of",
    "X" * 65,
    "$(cat /etc/passwd)",
    "'; DROP GRAPH sever_demo; --",
    "MEMBER_OF\n",   # pydantic's rust-regex $ is strict: trailing newline dies
]


def test_cut_request_accepts_valid_input():
    req = CutRequest(src=HERO, dst=HERO, rel="MEMBER_OF", approved=True)
    assert req.approved_by == "console-operator"
    assert req.rel == "MEMBER_OF"


def test_cut_request_accepts_camel_case_entra_rel():
    # AZ rels are legitimate product rel types (jewels.TRAVERSAL_RELS)
    for rel in ("AZOwns", "AZMemberOf", "AZVMAdminLogin"):
        assert CutRequest(src=HERO, dst=HERO, rel=rel, approved=True).rel == rel


def test_cut_request_rejects_oversized_fields():
    with pytest.raises(ValidationError):
        CutRequest(src="S-" * 200, dst=HERO, rel="MEMBER_OF", approved=True)
    with pytest.raises(ValidationError):
        CutRequest(src=HERO, dst="S-" * 200, rel="MEMBER_OF", approved=True)
    with pytest.raises(ValidationError):
        CutRequest(src=HERO, dst=HERO, rel="M" * 200, approved=True)
    with pytest.raises(ValidationError):
        CutRequest(src=HERO, dst=HERO, rel="MEMBER_OF", approved=True, approved_by="x" * 500)


def test_cut_request_rejects_injection_rels():
    for rel in INJECTION_RELS:
        with pytest.raises(ValidationError):
            CutRequest(src=HERO, dst=HERO, rel=rel, approved=True)


def test_finding_request_accepts_valid_input_and_defaults():
    req = FindingRequest(subject=HERO)
    assert req.kind == "credential_breach"
    assert req.target is None and req.rel is None
    # audit3/console-logic: ace_granted must carry a REAL grant (target+rel,
    # target != subject) — a target-only or self-grant is a phantom mutation.
    req = FindingRequest(kind="ace_granted", subject=HERO,
                         target="S-1-5-21-t-2102", rel="GENERIC_ALL")
    assert (req.kind, req.target, req.rel) == ("ace_granted", "S-1-5-21-t-2102", "GENERIC_ALL")


def test_finding_request_rejects_oversized_fields():
    with pytest.raises(ValidationError):
        FindingRequest(kind="k" * 200, subject=HERO)
    with pytest.raises(ValidationError):
        FindingRequest(subject="S-1-" + "9" * 10_000)
    with pytest.raises(ValidationError):
        FindingRequest(subject=HERO, target="T" * 500)
    with pytest.raises(ValidationError):
        FindingRequest(subject=HERO, rel="R" * 200)


def test_finding_request_rejects_injection_rels():
    for rel in INJECTION_RELS:
        with pytest.raises(ValidationError):
            FindingRequest(kind="ace_granted", subject=HERO, target=HERO, rel=rel)


# ---- audit2/api-contract regression: the human gate is a STRICT boolean ----

TRUTHY_NON_BOOL = [1, 0, 1.0, 0.0, 5, "true", "TRUE", "True", "false", "no",
                   "yes", "on", "off", "1", "0", [], [True], {}, {"approved": True}, None]


def test_cut_gate_rejects_every_truthy_non_bool():
    """The bypass that executed real interdictions pre-fix.

    Pydantic lax ``bool`` coerced each of these to True, the handler's
    ``approved is not True`` gate passed, and POST /api/cut removed live
    edges. StrictBool must answer all of them with 422.
    """
    for bad in TRUTHY_NON_BOOL:
        with pytest.raises(ValidationError):
            CutRequest(src=HERO, dst=HERO, rel="MEMBER_OF", approved=bad)


def test_cut_gate_accepts_only_real_booleans():
    assert CutRequest(src=HERO, dst=HERO, rel="MEMBER_OF", approved=True).approved is True
    assert CutRequest(src=HERO, dst=HERO, rel="MEMBER_OF", approved=False).approved is False


def test_required_strings_must_be_non_empty():
    with pytest.raises(ValidationError):
        CutRequest(src="", dst=HERO, rel="MEMBER_OF", approved=True)
    with pytest.raises(ValidationError):
        CutRequest(src=HERO, dst="", rel="MEMBER_OF", approved=True)
    with pytest.raises(ValidationError):
        CutRequest(src=HERO, dst=HERO, rel="MEMBER_OF", approved=True, approved_by="")
    with pytest.raises(ValidationError):
        FindingRequest(subject="")
    with pytest.raises(ValidationError):
        FindingRequest(subject=HERO, kind="")
    with pytest.raises(ValidationError):
        FindingRequest(subject=HERO, target="")


def test_lone_surrogates_are_rejected_not_poisonous():
    """\\ud800 escapes crash UTF-8 encodes downstream (response render AND the
    receipts ledger read path — one such event 500s every future
    GET /api/receipts). They must die at the schema layer as 422."""
    with pytest.raises(ValidationError):
        CutRequest(src="\ud800", dst=HERO, rel="MEMBER_OF", approved=True)
    with pytest.raises(ValidationError):
        CutRequest(src=HERO, dst=HERO, rel="MEMBER_OF", approved=True, approved_by="\udfff")
    with pytest.raises(ValidationError):
        FindingRequest(kind="\ud800", subject=HERO)
    with pytest.raises(ValidationError):
        FindingRequest(subject="\ud800")
    with pytest.raises(ValidationError):
        FindingRequest(subject=HERO, target="\ud83d")   # lone high surrogate


def test_valid_astral_chars_still_pass():
    """Real emoji (surrogate PAIRS) reassemble in json.loads and encode fine —
    the utf-8 validator must not over-reject them. (audit3: the target probe
    uses a non-granting kind — ace_granted now requires target+rel.)"""
    emoji = "\U0001f512"  # 🔒 padlock
    req = FindingRequest(kind="cross_domain_trust", subject=HERO, target=emoji)
    assert req.target == emoji
    req = CutRequest(src=emoji, dst=HERO, rel="MEMBER_OF", approved=True)
    assert req.src == emoji


# ---- audit3/console-logic: honest rejection of impossible findings ----

def test_known_kinds_are_exactly_the_attack_map_vocabulary():
    from sever.console.schemas import KNOWN_FINDING_KINDS
    from sever.findings.attack_map import ATTACK_MAP

    assert set(KNOWN_FINDING_KINDS) == set(ATTACK_MAP) == {
        "credential_breach", "kerberoastable_spn", "ace_granted", "dcsync_right",
        "cross_domain_trust", "cert_esc1",
    }


def test_unknown_finding_kind_is_rejected_not_narrated():
    """Pre-fix (live-verified): kind='totally_unknown_kind' was accepted and
    answered with a FABRICATED 'T1595.002 Vulnerability Scanning' label; a
    kind of '<img src=x onerror=1>' was accepted too."""
    for kind in ("totally_unknown_kind", "<img src=x onerror=1>",
                 "credential breach", "Credential_Breach", "x" * 65):
        with pytest.raises(ValidationError):
            FindingRequest(kind=kind, subject=HERO)


def test_every_documented_kind_is_accepted():
    from sever.console.schemas import KNOWN_FINDING_KINDS

    for kind in KNOWN_FINDING_KINDS:
        # ace_granted is only valid WITH a real grant; the informational
        # kinds accept the targetless replay shape.
        body = ({"kind": "ace_granted", "subject": HERO, "target": "S-1-5-21-t-2102",
                 "rel": "GENERIC_ALL"} if kind == "ace_granted"
                else {"kind": kind, "subject": HERO})
        req = FindingRequest(**body)
        assert req.kind == kind


def test_ace_granted_requires_a_real_grant():
    """Pre-fix (live-verified): ace_granted WITHOUT target/rel answered 200
    with applied:false while the narration claimed the graph 'now carries a
    new abusable edge' — a mutation that never happened."""
    with pytest.raises(ValidationError):
        FindingRequest(kind="ace_granted", subject=HERO)                       # nothing granted
    with pytest.raises(ValidationError):
        FindingRequest(kind="ace_granted", subject=HERO, target="S-1-5-21-t-2102")  # target only
    with pytest.raises(ValidationError):
        FindingRequest(kind="ace_granted", subject=HERO, rel="GENERIC_ALL")    # rel only
    ok = FindingRequest(kind="ace_granted", subject=HERO,
                        target="S-1-5-21-t-2102", rel="GENERIC_ALL")
    assert (ok.target, ok.rel) == ("S-1-5-21-t-2102", "GENERIC_ALL")


def test_self_edge_grant_is_rejected():
    """add_edge refuses src==dst; accepting the finding would narrate a
    phantom grant (pre-fix live-verified)."""
    with pytest.raises(ValidationError):
        FindingRequest(kind="ace_granted", subject=HERO, target=HERO, rel="GENERIC_ALL")
    with pytest.raises(ValidationError):
        FindingRequest(kind="cross_domain_trust", subject=HERO, target=HERO, rel="TRUSTED_BY")


def test_informational_kinds_still_accept_targetless_shape():
    """cross_domain_trust without target+rel is a legitimate informational
    finding (timeline F-004) — the ace_granted rule must not over-reject."""
    req = FindingRequest(kind="cross_domain_trust", subject=HERO)
    assert req.target is None and req.rel is None
    req = FindingRequest(kind="kerberoastable_spn", subject=HERO, rel="GENERIC_ALL")
    assert req.rel == "GENERIC_ALL"   # rel is inert without target; no grant claimed
