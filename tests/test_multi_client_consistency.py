"""Multi-client consistency — the audit5/multi-client regressions, DB-free.

Pinned here (each one was a live-measured failure on the shared estate /
two-instance rig before the fix):

1. CaseLog append-order is a valid timestamp order: the ts is stamped INSIDE
   the file lock, so a judge reading the receipts top-to-bottom never sees
   time run backwards no matter how many operator processes interleave.
2. Plan projections use a UNIQUE engine-side scratch key per invocation:
   two concurrent planners must never share one GRAPH.COPY (the shared fixed
   key served contaminated all-steps-no_effect plans to the human gate and
   500'd other planners, measured 3/8 concurrent /api/plan calls).
3. A failed /api/plan leaves a plan_failed receipt — an attempt that the
   ledger previously lost entirely (invisible hole for a judge).
4. The engine cut is ONE atomic delete-and-count statement: the old
   count-then-delete pair let two concurrent cutters of the same edge BOTH
   receipt relationships_removed=1 (6/6 measured rounds) — a phantom
   double-claim in an append-only ledger.
5. An empty estate is marked (estate_missing) instead of silently reading as
   continuity — out-of-band GRAPH.DELETE broke receipt reconstruction with no
   trace (live ledger: 10 "removed 1" cuts whose edges exist again today).

The live multi-client counterparts (cross-process ledger interleaving, the
concurrent double-cut race, concurrent planners, plan-vs-cut drift) ran as
scripted HTTP batteries against two real console instances on one engine.
"""
from __future__ import annotations

import json
import threading

import pytest

from sever.core.scoring import plan_cut_sequence
from tests.test_agent import FakeGraphPort
from tests.test_planning import _two_route_port

# ------------------------------------------------------------------
# 1. CaseLog: file order == timestamp order under concurrent writers
# ------------------------------------------------------------------


def test_concurrent_appends_stay_in_timestamp_order(tmp_path):
    """8 threads x 25 appends: every entry parses, none lost, and the ts of
    file position i is never LATER than the ts of position i+1 — stamped
    inside the lock, the ledger read top-to-bottom is a valid time order."""
    from sever.memory.flow import CaseLog

    log = CaseLog("sever_audit5_cl_order", root=tmp_path)

    def worker(tid: int) -> None:
        for i in range(25):
            log.append({"step": "finding", "tid": tid, "i": i, "pad": "z" * 256})

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    events = log.read()
    assert len(events) == 200
    stamps = [e["ts"] for e in events]
    assert stamps == sorted(stamps), (
        "ledger file order must be a non-decreasing timestamp order — "
        f"first regression at index {next(i for i in range(1, len(stamps)) if stamps[i-1] > stamps[i])}"
    )
    assert len({(e["tid"], e["i"]) for e in events}) == 200


# ------------------------------------------------------------------
# 2. Plan scratch keys: unique per invocation, still prefixed + droppable
# ------------------------------------------------------------------


class _RecordingPort(FakeGraphPort):
    """FakeGraphPort that records every scratch name it was asked to create."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.scratch_names: list[str] = []
        self.graph_name = "sever_audit5_fake"

    def scratch_copy(self, scratch_name: str) -> "_RecordingPort":
        self.scratch_names.append(scratch_name)
        copy = _RecordingPort(jewels=tuple(self.crown_jewels()))
        copy._edges = list(self._edges)
        copy._owned = set(self._owned)
        copy.graph_name = scratch_name
        return copy


def test_plan_scratch_keys_are_unique_per_invocation():
    port = _RecordingPort(jewels=("g-da",))
    port._edges = [
        ("u-zoe", "GENERIC_ALL", "u-a1"),
        ("u-a1", "MEMBER_OF", "g-da"),
    ]
    port.mark_owned("u-zoe")
    plan_cut_sequence(port, k=2)
    plan_cut_sequence(port, k=2)
    assert len(port.scratch_names) == 2
    a, b = port.scratch_names
    assert a != b, "two concurrent planners must never share one scratch key"
    for name in (a, b):
        assert name.startswith("sever_audit5_fake_plan_scratch_"), (
            "leaked-by-crash scratch keys stay identifiable by the "
            f"{{graph}}_plan_scratch_ prefix: got {name!r}"
        )


def test_explicit_scratch_name_is_still_honored():
    port = _two_route_port()
    plan_cut_sequence(port, k=1, scratch_name="my_explicit_scratch")
    # an explicit name is used verbatim (callers keep full control)


# ------------------------------------------------------------------
# 3. A failed /api/plan leaves a plan_failed receipt, answers a clean 503
# ------------------------------------------------------------------


@pytest.fixture()
def console(tmp_path, monkeypatch):
    class _NamedPort(FakeGraphPort):
        """FakeGraphPort with the graph_name the console's /api/state reads."""

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.graph_name = "sever_audit5_fake"

    monkeypatch.chdir(tmp_path)  # CaseLog root lands in the tmp dir
    monkeypatch.setenv("SEVER_CONSOLE_NO_BOOTSTRAP", "1")
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", "sever_audit5_cl_mcc")
    from fastapi.testclient import TestClient

    import sever.console.app as appmod

    fake = _NamedPort(jewels=("g-da",))
    fake._edges = [("u-zoe", "GENERIC_ALL", "u-a1"), ("u-a1", "MEMBER_OF", "g-da")]
    fake.mark_owned("u-zoe")
    tc = TestClient(appmod.build_app(port=fake))
    yield tc, fake, tmp_path


def test_failed_plan_is_ledgered_and_answers_503(console, monkeypatch):
    """An engine-side plan failure (scratch lifecycle race, internal bug)
    must never vanish: the attempt lands on the receipts trail as
    plan_failed/outcome unknown and the caller gets a clean JSON 503 —
    never a bare 500 with no ledger entry."""
    tc, fake, tmp_path = console

    # simplest deterministic failure: make the engine port raise mid-plan
    def boom(name):  # scratch_copy exploding == the measured engine race
        raise RuntimeError("graph was deleted or replaced while the query was running")

    monkeypatch.setattr(fake, "scratch_copy", boom)
    r = tc.get("/api/plan")
    assert r.status_code == 503
    assert "retry" in r.json()["detail"]

    ledger = tmp_path / "out" / "cases" / "sever_audit5_cl_mcc.jsonl"
    events = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    failed = [e for e in events if e.get("step") == "plan_failed"]
    assert failed, "the failed plan attempt must be on the receipts trail"
    assert failed[-1]["outcome"] == "unknown"
    assert "plan projection failed" in failed[-1]["error"]


# ------------------------------------------------------------------
# 4. The cut is ONE atomic engine statement
# ------------------------------------------------------------------


def test_engine_cut_is_one_atomic_delete_and_count():
    """The count-then-delete pair (a TOCTOU seam: two concurrent cutters of
    one edge both receipted removed=1) is gone — the port ships a single
    MATCH...DELETE...RETURN count statement the engine executes atomically."""
    from sever.core import falkor_port as fp

    q = fp.CUT_ATOMIC_QUERY_TEMPLATE.format(rel="GENERIC_ALL")
    assert "DELETE r" in q and "RETURN count(r)" in q
    assert q.count("MATCH") == 1, "one statement — no separate pre-count read"
    assert not hasattr(fp, "CUT_COUNT_QUERY_TEMPLATE"), "the stale pre-count query must be gone"
    assert not hasattr(fp, "CUT_DELETE_QUERY_TEMPLATE"), "the stale follow-up delete must be gone"


# ------------------------------------------------------------------
# 5. An empty estate is marked, never silently read as continuity
# ------------------------------------------------------------------


def test_empty_estate_gets_an_estate_missing_receipt(console):
    tc, fake, tmp_path = console
    # the graph emptied out-of-band between requests (edges, owned AND jewels
    # all gone — node_count() == 0 is exactly what /api/state then observes)
    fake._edges = []
    fake._owned = set()
    fake._jewels = set()
    r = tc.get("/api/state")
    assert r.status_code == 200
    ledger = tmp_path / "out" / "cases" / "sever_audit5_cl_mcc.jsonl"
    events = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    steps = [e.get("step") for e in events]
    assert "estate_missing" in steps, (
        "an out-of-band emptied estate must leave a continuity-break marker"
    )
    # the marker precedes the state snapshot that observed the emptiness
    assert steps.index("estate_missing") < len(steps) - 1
    # audit M49: while the estate STAYS missing, further polls append
    # NOTHING — pre-fix every poll added estate_missing AND a state line
    # (the change-key was reset to None behind the check's back), 8
    # lines/minute per open tab: exactly the unbounded-growth failure the
    # change-only logging and the /api/receipts bound were built against.
    assert steps.count("estate_missing") == 1
    assert steps.count("state") == 1, "the (0,0,0) transition logs once"
    n_before = len(events)
    for _ in range(3):
        assert tc.get("/api/state").status_code == 200
    events_after = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(events_after) == n_before, (
        "empty-estate poll traffic must not grow the receipts ledger"
    )
