"""Regression armor for the audit5/brutal-edge HIGH finding + the lax-int gap.

live-verified pre-fix (2026-10-16, https://sever-console.onrender.com):
a NUL byte (U+0000) in subject/target/dst sailed past every schema check,
reached FalkorDB as a query parameter, and the engine's
ResponseError("Failed to parse the value of parameter") escaped the console's
outage handler as a bare HTTP 500 on /api/finding, /api/cut and
/api/plan/execute — the module's own "never a 500" contract broken.
These tests pin the schema-level rejection: control chars die at 422 before
any engine contact, and the plan projection accepts strict bounded ints only.

DB-free: pure pydantic contract, no engine, no TestClient.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from sever.console.schemas import (
    CutRequest,
    FindingRequest,
    PlanExecuteRequest,
    PlanStep,
)


def _valid_step(**over: object) -> dict:
    step = {
        "src": "S-1-5-21-1-2-3-1105",
        "dst": "S-1-5-21-1-2-3-512",
        "rel": "MemberOf",
        "projected_reachability": 0,
    }
    step.update(over)
    return step


class TestControlCharRejection:
    """Every string that can flow toward a query parameter rejects control chars."""

    @pytest.mark.parametrize("evil", ["\x00", "TONY\x00", "T\x00ONY", "\x1b[31m", "\x7f", "\x9f", "A\x00B\x00C"])
    def test_finding_subject_rejected(self, evil: str) -> None:
        with pytest.raises(ValidationError, match="control"):
            FindingRequest(kind="credential_breach", subject=evil)

    @pytest.mark.parametrize("evil", ["\x00", "user\x00@dom", "\x1b"])
    def test_finding_target_rejected(self, evil: str) -> None:
        with pytest.raises(ValidationError, match="control"):
            FindingRequest(kind="ace_granted", subject="S-1-5-21-1-2-3-1105",
                           target=evil, rel="GenericAll")

    @pytest.mark.parametrize("field", ["src", "dst"])
    def test_cut_fields_rejected(self, field: str) -> None:
        payload = {"src": "S-1-5-21-1-2-3-1105", "dst": "S-1-5-21-1-2-3-512",
                   "rel": "MemberOf", "approved": True}
        payload[field] = "pre\x00fix"
        with pytest.raises(ValidationError, match="control"):
            CutRequest(**payload)

    @pytest.mark.parametrize("field", ["src", "dst"])
    def test_plan_step_fields_rejected(self, field: str) -> None:
        payload = _valid_step()
        payload[field] = "x\x00x"
        with pytest.raises(ValidationError, match="control"):
            PlanStep(**payload)

    def test_approved_by_rejected(self) -> None:
        with pytest.raises(ValidationError, match="control"):
            PlanExecuteRequest(approved=True, approved_by="op\x00erator", steps=[_valid_step()])

    def test_legitimate_names_still_pass(self) -> None:
        # real objectids/SIDs/GUIDs/labels never contain control chars — the
        # guard must have zero false positives on the demo estate's shapes
        req = FindingRequest(kind="credential_breach", subject="S-1-5-21-2697957641-2271029196-387917394-2110")
        assert req.subject.startswith("S-1-5-21")
        cut = CutRequest(src="3892f15b-2264-4927-8366-74b0f7f49761",
                         dst="S-1-5-21-1-2-3-512", rel="GenericAll", approved=True)
        assert cut.rel == "GenericAll"
        step = PlanStep(**_valid_step())
        assert step.projected_reachability == 0


class TestStrictProjectionInt:
    """audit5/brutal-edge: the projection echoed by the UI must be a strict,
    bounded int — lax pydantic coercion accepted "3" (executed a plan, 200)
    and 2**70 (200)."""

    def test_string_coercion_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PlanStep(**_valid_step(projected_reachability="3"))

    def test_float_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PlanStep(**_valid_step(projected_reachability=3.0))

    def test_bool_rejected(self) -> None:
        # bool is an int subclass — StrictInt must refuse it
        with pytest.raises(ValidationError):
            PlanStep(**_valid_step(projected_reachability=True))

    def test_absurd_upper_bound_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PlanStep(**_valid_step(projected_reachability=2**70))

    def test_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PlanStep(**_valid_step(projected_reachability=-1))

    def test_zero_and_realistic_values_pass(self) -> None:
        assert PlanStep(**_valid_step()).projected_reachability == 0
        assert PlanStep(**_valid_step(projected_reachability=10)).projected_reachability == 10
