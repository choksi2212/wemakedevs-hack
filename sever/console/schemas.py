"""Console request schemas (audit/security).

Pure pydantic models, deliberately engine-free: ``sever.console.app`` connects
to FalkorDB at import time, so the request models live here to stay importable
— and their input validation testable — without any engine.

Every string that can flow toward a query is size-capped; ``rel`` fields carry
a syntax pattern that mirrors the Cypher injection guard
``sever.core.falkor_port._valid_rel``. The charset is the security property:
[A-Za-z0-9_] holds no Cypher metacharacter, so a schema-valid rel can never
break out of the ``-[r:{rel}]->`` slot, and hostile payloads die as HTTP 422
before they reach a query template. Mixed case is allowed on purpose — the
product's traversal set (jewels.TRAVERSAL_RELS) contains camelCase Entra rel
types (AZOwns, AZMemberOf, ...) alongside the uppercase AD rel types.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

# Same anchor as falkor_port._valid_rel (pydantic's rust regex `$` is strict:
# it does not match before a trailing newline).
REL_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{0,63}$"


class CutRequest(BaseModel):
    src: str = Field(max_length=256)   # objectid / SID / GUID — never longer
    dst: str = Field(max_length=256)
    rel: str = Field(max_length=64, pattern=REL_PATTERN)
    approved: bool
    approved_by: str = Field(default="console-operator", max_length=128)


class FindingRequest(BaseModel):
    kind: str = Field(default="credential_breach", max_length=64)
    subject: str = Field(max_length=256)   # objectid / SID / GUID — never longer
    target: str | None = Field(default=None, max_length=256)
    rel: str | None = Field(default=None, max_length=64, pattern=REL_PATTERN)
