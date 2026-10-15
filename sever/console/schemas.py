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
"""
from __future__ import annotations

from pydantic import BaseModel, Field, StrictBool, field_validator

# Same anchor as falkor_port._valid_rel (pydantic's rust regex `$` is strict:
# it does not match before a trailing newline).
REL_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{0,63}$"


def _utf8_encodable(value: str | None) -> str | None:
    """Reject strings that cannot round-trip UTF-8 (lone surrogates -> 422)."""
    if value is None:
        return value
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("must not contain lone surrogates (non-UTF-8 encodable)")
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
