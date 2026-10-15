"""Console request schemas (audit/security).

Pure pydantic models, deliberately engine-free: ``sever.console.app`` connects
to FalkorDB at import time, so the request models live here to stay importable
— and their input validation testable — without any engine.

Three security properties (audit2/api-contract):

1. Size caps + rel syntax pattern. Every string that can flow toward a query
   is size-capped; ``rel`` fields carry a syntax pattern that mirrors the
   Cypher injection guard ``sever.core.falkor_port._valid_rel``. The charset
   is the security property: [A-Za-z0-9_] holds no Cypher metacharacter, so a
   schema-valid rel can never break out of the ``-[r:{rel}]->`` slot, and
   hostile payloads die as HTTP 422 before they reach a query template.
   Mixed case is allowed on purpose — the product's traversal set
   (jewels.TRAVERSAL_RELS) contains camelCase Entra rel types (AZOwns,
   AZMemberOf, ...) alongside the uppercase AD rel types. Required strings
   are also ``min_length=1``: an empty objectid is never a valid key.

2. ``approved`` is a StrictBool. Pydantic's lax ``bool`` coerces JSON
   ``1``, ``1.0``, ``"true"``, ``"TRUE"``, ``"yes"``, ``"on"`` and ``"1"`` to
   ``True`` — which made any truthy scalar count as human approval and let
   POST /api/cut execute interdictions without a real boolean (verified
   end-to-end on the audit instance: ``{"approved": 1}`` removed a live
   edge). StrictBool answers all of those with 422; only the exact JSON
   booleans ``true``/``false`` ever reach the handler's ``is not True`` gate
   check.

3. UTF-8 round-trip validator. Lone surrogates (JSON ``"\\ud800"`` escapes)
   pass pydantic's plain ``str`` check but crash every downstream UTF-8
   encode: the 200/500 response render (``json.dumps(ensure_ascii=False)``
   + ``.encode("utf-8")``) raises, AND the accepted event poisons the
   append-only receipts ledger so every future GET /api/receipts 500s until
   the JSONL is hand-edited. The validator rejects non-encodable strings as
   422 here — before any mutation, any ledger write, any response render.
   Valid surrogate pairs (real astral characters) reassemble in json.loads
   and encode fine, so they are NOT affected.

audit3/console-logic — honest rejection of impossible findings:
- ``kind`` is a closed vocabulary (the ATTACK_MAP keys). Pre-fix an unknown
  kind was accepted (200) and narrated with a FABRICATED ATT&CK label —
  live-verified: ``kind="totally_unknown_kind"`` answered
  ``T1595.002 Active Scanning: Vulnerability Scanning`` and wrote a phantom
  finding to the receipts ledger. Unknown kinds are 422 here, before any
  narration or ledger write.
- ``ace_granted`` IS its edge grant: without both ``target`` and ``rel``
  nothing is granted, yet the canned narration asserted the graph "now
  carries a new abusable edge" (live-verified 200, applied:false). Same for
  a self-grant (``target == subject``): the engine rejects self-edges, so
  the narration would claim a mutation that never happened. Both are 422.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, StrictBool, field_validator, model_validator

from sever.findings.attack_map import ATTACK_MAP

# Same anchor as falkor_port._valid_rel (pydantic's rust regex `$` is strict:
# it does not match before a trailing newline).
REL_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{0,63}$"

# Finding kinds are the closed ATT&CK vocabulary the narration map defines —
# anything else must die at the schema, not get a fabricated technique label.
KNOWN_FINDING_KINDS: tuple[str, ...] = tuple(sorted(ATTACK_MAP))


def _utf8_encodable(value: str | None) -> str | None:
    """Reject strings that cannot round-trip UTF-8 (lone surrogates -> 422)."""
    if value is None:
        return value
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("must not contain lone surrogates (non-UTF-8 encodable)")
    return value


def _known_kind(value: str) -> str:
    """Reject unknown finding kinds — no fabricated ATT&CK labels, no phantom
    ledger entries (audit3/console-logic, live-verified pre-fix behavior)."""
    if value not in ATTACK_MAP:
        raise ValueError(
            f"unknown finding kind {value!r}: expected one of "
            f"{', '.join(KNOWN_FINDING_KINDS)}"
        )
    return value


class CutRequest(BaseModel):
    src: str = Field(min_length=1, max_length=256)   # objectid / SID / GUID — never longer, never empty
    dst: str = Field(min_length=1, max_length=256)
    rel: str = Field(max_length=64, pattern=REL_PATTERN)
    approved: StrictBool
    approved_by: str = Field(default="console-operator", min_length=1, max_length=128)

    _utf8 = field_validator("src", "dst", "rel", "approved_by")(_utf8_encodable)


class FindingRequest(BaseModel):
    kind: str = Field(default="credential_breach", min_length=1, max_length=64)
    subject: str = Field(min_length=1, max_length=256)   # objectid / SID / GUID — never longer, never empty
    target: str | None = Field(default=None, min_length=1, max_length=256)
    rel: str | None = Field(default=None, max_length=64, pattern=REL_PATTERN)

    _utf8 = field_validator("kind", "subject", "target", "rel")(_utf8_encodable)
    _kind = field_validator("kind")(_known_kind)

    @model_validator(mode="after")
    def _grant_shape(self) -> "FindingRequest":
        # ace_granted IS its edge grant: without target+rel nothing is granted
        # and the canned T1098 narration would claim a mutation that never
        # happened (live-verified pre-fix: 200, applied:false, narrating
        # "the identity graph now carries a new abusable edge").
        if self.kind == "ace_granted" and not (self.target and self.rel):
            raise ValueError(
                "kind 'ace_granted' requires both 'target' and 'rel' — "
                "without them no grant exists and the narration would claim "
                "a mutation that never happened"
            )
        # Self-grants are rejected by the engine (add_edge returns False on
        # src == dst); accepting one would narrate another phantom grant.
        if self.target and self.rel and self.target == self.subject:
            raise ValueError(
                "'target' must differ from 'subject' — self-grants are "
                "rejected by the engine and would narrate a phantom mutation"
            )
        return self


class PlanStep(BaseModel):
    """One step of a remediation plan the operator is approving. The step
    echoes back the projection the UI rendered (``projected_reachability``)
    so the drift check in execute_plan can honestly compare what the
    operator approved against what the engine measures."""
    src: str = Field(min_length=1, max_length=256)
    dst: str = Field(min_length=1, max_length=256)
    rel: str = Field(max_length=64, pattern=REL_PATTERN)
    projected_reachability: int = Field(ge=0)

    _utf8 = field_validator("src", "dst", "rel")(_utf8_encodable)


class PlanExecuteRequest(BaseModel):
    """The plan-execution gate. ``approved`` is the same StrictBool contract
    as CutRequest: only the exact JSON booleans true/false ever reach the
    handler, which still checks ``approved is True`` — a plan is N cuts and
    every one of them stays behind the human gate, one approved payload
    listing exactly the steps the operator reviewed."""
    approved: StrictBool
    approved_by: str = Field(default="console-operator", min_length=1, max_length=128)
    steps: list[PlanStep] = Field(min_length=1, max_length=10)

    _utf8 = field_validator("approved_by")(_utf8_encodable)
