"""Console resilience — engine-down mid-mutation (audit3/console-logic).

Engine-free: build_app(port=...) is fed a fake port whose engine can be
killed at will. The live counterpart ran on ryzen: a real console against a
private FalkorDB container, docker-stopped between /api/finding and /api/cut
(pre-fix live evidence: bare 500 "Internal Server Error" on every route while
the ledger stayed intact).
"""
from __future__ import annotations

import pytest

from sever.core.jewels import DEFAULT_HOP_CAP
from sever.core.port import GraphPort

ALICE = "S-1-5-21-a"
TIER1 = "S-1-5-21-t1"
DA = "S-1-5-21-512"


def _conn_refused():
    from redis.exceptions import ConnectionError

    return ConnectionError("Error 10061 connecting to 127.0.0.1:6379. Connection refused.")


class _Res:
    def __init__(self, rows):
        self.result_set = rows


class _FakeGraphHandle:
    """Duck-types the falkordb graph handle for the console's direct queries
    (``_name`` and the ``_objectid_exists`` probe)."""

    def __init__(self, names: dict[str, str]):
        self.names = names
        self.dead = False

    def query(self, q, params=None, timeout=None):
        if self.dead:
            raise _conn_refused()
        p = params or {}
        if "count(n)" in q:  # honest-rejection existence probe
            return _Res([[1 if p.get("o", "") in self.names else 0]])
        if "n.name AS name" in q:
            return _Res([[self.names.get(p.get("o", ""))]])
        return _Res([])


class _FakePort(GraphPort):
    """One chain: ALICE -[MEMBER_OF]-> TIER1 -[MEMBER_OF]-> DA (crown jewel)."""

    def __init__(self) -> None:
        self.graph = _FakeGraphHandle({ALICE: "ALICE", TIER1: "TIER1", DA: "DOMADM"})
        self.graph_name = "sever_audit3_cl_resil"
        self._edges: list[tuple[str, str, str]] = [
            (ALICE, "MEMBER_OF", TIER1), (TIER1, "MEMBER_OF", DA),
        ]
        self._owned: set[str] = set()
        self.ops_dead = False  # port-level engine death (snapshot/mutation)

    def _check(self) -> None:
        if self.ops_dead:
            raise _conn_refused()

    # ---- GraphPort protocol ----
    def load(self, graph) -> None:  # pragma: no cover - fake is preloaded
        pass

    def node_count(self) -> int:
        self._check()
        return len(self.graph.names)

    def edge_count(self) -> int:
        self._check()
        return len(self._edges)

    def mark_owned(self, objectid: str) -> None:
        self._check()
        self._owned.add(objectid)

    def owned_ids(self) -> list[str]:
        self._check()
        return sorted(self._owned)

    def user_objectids(self) -> list[str]:
        # the benign-usage sampling pool (audit4): this estate's one User.
        # _check() FIRST so an engine-dead /api/proposal still surfaces the
        # connection error (clean 503) instead of a missing-method TypeError.
        self._check()
        return [ALICE]

    def crown_jewels(self) -> list[str]:
        self._check()
        return [DA]

    def reachability(self, hop_cap: int = DEFAULT_HOP_CAP) -> int:
        self._check()
        return sum(1 for o in self._owned if self.paths_to_jewels(o, hop_cap))

    def paths_to_jewels(self, objectid: str, hop_cap: int = DEFAULT_HOP_CAP,
                        ties: bool = False):
        self._check()
        if (objectid == ALICE and (ALICE, "MEMBER_OF", TIER1) in self._edges
                and (TIER1, "MEMBER_OF", DA) in self._edges):
            return [[(ALICE, "MEMBER_OF", TIER1), (TIER1, "MEMBER_OF", DA)]]
        return []

    def edge_frequency(self, hop_cap: int = DEFAULT_HOP_CAP):
        self._check()
        freq: dict[tuple[str, str, str], int] = {}
        for o in self.owned_ids():
            for path in self.paths_to_jewels(o, hop_cap):
                for hop in path:
                    freq[hop] = freq.get(hop, 0) + 1
        return freq

    def add_edge(self, src: str, dst: str, rel: str, props=None) -> bool:
        self._check()
        if src == dst:
            return False
        key = (src, rel, dst)
        if key in self._edges:
            return False
        self._edges.append(key)
        return True

    def cut(self, src: str, dst: str, rel: str) -> int:
        self._check()
        victims = [e for e in self._edges if e == (src, rel, dst)]
        self._edges = [e for e in self._edges if e != (src, rel, dst)]
        return len(victims)

    def profile(self, query, params=None) -> str:  # pragma: no cover
        return "fake-profile"

    def receipt(self):  # pragma: no cover
        return {"backend": "fake"}


@pytest.fixture()
def console(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # CaseLog root lands in the tmp dir
    monkeypatch.setenv("SEVER_CONSOLE_NO_BOOTSTRAP", "1")
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", "sever_audit3_cl_resil")
    from fastapi.testclient import TestClient

    import sever.console.app as appmod

    fake = _FakePort()
    tc = TestClient(appmod.build_app(port=fake))
    yield tc, fake
    # the ledger file (when anything was written) must still be pristine JSONL
    ledger = tmp_path / "out" / "cases" / "sever_audit3_cl_resil.jsonl"
    if ledger.exists():
        import json

        for line in ledger.read_text(encoding="utf-8").splitlines():
            if line.strip():
                json.loads(line)


def test_finding_happy_path_reports_applied_true(console):
    tc, fake = console
    r = tc.post("/api/finding", json={"kind": "credential_breach", "subject": ALICE})
    assert r.status_code == 200
    body = r.json()
    assert body["applied"] is True  # audit3: a breach that sticks IS a mutation
    assert body["reachability"] == 1


def test_unknown_principal_is_a_400_not_a_phantom(console):
    tc, _ = console
    r = tc.post("/api/finding", json={"kind": "credential_breach",
                                     "subject": "S-1-5-21-does-not-exist"})
    assert r.status_code == 400
    assert "unknown subject" in r.json()["detail"]
    r = tc.post("/api/finding", json={"kind": "ace_granted", "subject": ALICE,
                                      "target": "S-1-5-21-ghost", "rel": "GENERIC_ALL"})
    assert r.status_code == 400
    assert "unknown target" in r.json()["detail"]
    # no phantom finding entered the receipts ledger
    assert not any(e.get("step") == "finding"
                   for e in tc.get("/api/receipts").json())


def test_engine_down_mid_mutation_is_clean_503_and_ledger_stays_honest(console):
    """The live audit's core scenario, reproduced deterministically: the
    engine dies between /api/finding and /api/cut."""
    tc, fake = console
    assert tc.post("/api/finding",
                   json={"kind": "credential_breach", "subject": ALICE}).status_code == 200

    # engine dies between finding and cut
    fake.ops_dead = True
    r = tc.post("/api/cut", json={"src": ALICE, "dst": TIER1, "rel": "MEMBER_OF",
                                  "approved": True, "approved_by": "resilience"})
    assert r.status_code == 503
    assert r.json()["detail"].startswith("engine unreachable")

    # a finding whose probe passes but whose triage dies mid-flight
    r = tc.post("/api/finding", json={"kind": "credential_breach", "subject": ALICE})
    assert r.status_code == 503

    # every read route 5xx cleanly — machine-readable JSON, never a bare 500
    for path in ("/api/state", "/api/paths", "/api/proposal"):
        r = tc.get(path)
        assert r.status_code == 503, path
        assert r.json()["detail"].startswith("engine unreachable")

    # ledger intact + honest: failed attempts recorded, no phantom success
    r = tc.get("/api/receipts")
    assert r.status_code == 200
    recs = r.json()
    steps = [e["step"] for e in recs]
    assert "cut_failed" in steps and "finding_failed" in steps
    cut_failed = next(e for e in recs if e["step"] == "cut_failed")
    assert cut_failed["outcome"] == "unknown"
    assert cut_failed["cut"] == {"src": ALICE, "dst": TIER1, "rel": "MEMBER_OF"}
    assert not any(
        e["step"] == "cut"
        and e["receipt"]["cut"]["src"] == ALICE and e["receipt"]["cut"]["dst"] == TIER1
        for e in recs
    ), "a cut that never completed must never be recorded as a success"

    # engine back: the console recovers in place
    fake.ops_dead = False
    assert tc.get("/api/state").status_code == 200
    assert tc.get("/api/receipts").status_code == 200


def test_engine_dead_before_the_probe_is_still_a_clean_503(console):
    tc, fake = console
    fake.graph.dead = True
    fake.ops_dead = True
    r = tc.post("/api/finding", json={"kind": "credential_breach", "subject": ALICE})
    assert r.status_code == 503
    assert r.json()["detail"].startswith("engine unreachable")
    # nothing was attempted — no failure line either
    assert all(e["step"] != "finding_failed" for e in tc.get("/api/receipts").json())



def test_api_health_is_a_cheap_engine_probe_and_writes_no_receipt(console):
    """audit5/deploy-audit: Render's HTTP health check has a 5-second window.
    /api/state runs five engine queries and measured 6-24s against the live
    FalkorDB Cloud under concurrent load — as the health path it caused an
    instance-restart loop that wiped the ephemeral ledger roughly every 10
    minutes. /api/health must touch the engine (one query — a dead engine
    still fails the check) yet never append a receipt, so health-check
    traffic cannot drown the demo ledger in `state` noise."""
    tc, fake = console
    r = tc.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["nodes"] == 3  # the fake estate: ALICE, TIER1, DA
    assert not any(e.get("step") == "health"
                   for e in tc.get("/api/receipts").json())


def test_engine_dead_health_503_discloses_no_infra_details(console):
    """audit5/deploy-audit: the 503 detail must not echo the raw redis-py
    message — it embeds the engine host:port, which is infrastructure
    disclosure on a public URL. The exception class is the whole story."""
    tc, fake = console
    fake.ops_dead = True
    r = tc.get("/api/health")
    assert r.status_code == 503
    detail = r.json()["detail"]
    assert detail.startswith("engine unreachable")
    assert "ConnectionError" in detail
    assert "127.0.0.1" not in detail and "6379" not in detail
    fake.ops_dead = False
    assert tc.get("/api/health").status_code == 200


# ---- audit5/live-e2e: bounded receipts tail (the unbounded-ledger 502s) ----


def test_receipts_response_is_bounded_to_the_newest_events(console):
    """GET /api/receipts must never ship the whole append-only ledger.

    Live finding (Oct 16 06:15Z): the public deployment's ledger grew with
    every poll (each /api/state appends a line) until GET /api/receipts —
    the only route that returns the full file — started dying at the proxy
    (502s) and the UI's receipts card froze. The endpoint now ships the
    newest ``limit`` events (default 200); the UI renders the newest 40.
    """
    tc, fake = console
    from sever.memory.flow import CaseLog

    lg = CaseLog("sever_audit3_cl_resil")
    for i in range(260):
        lg.append({"step": "state", "reachability": i})
    recs = tc.get("/api/receipts").json()
    assert len(recs) == 200, "default tail must be 200 events, not the full ledger"
    assert recs[-1]["reachability"] == 259, "newest-last order must be preserved"
    assert recs[0]["reachability"] == 60, "the tail starts at len-200"
    # explicit limit: bounded both ways, newest still last
    assert [r["reachability"] for r in tc.get("/api/receipts?limit=3").json()] == [257, 258, 259]
    assert len(tc.get("/api/receipts?limit=99999").json()) == 260  # cap 5000 -> whole (small) ledger
    assert len(tc.get("/api/receipts?limit=0").json()) == 1  # degenerate clamps to 1, never 0


def test_receipts_still_returns_everything_while_small(console):
    """The bound must be invisible for young ledgers: a small ledger ships
    in full (no truncation marker, same order) — the API contract the
    existing console tests and the demo receipts rely on."""
    tc, fake = console
    tc.get("/api/state")  # appends the first state line
    recs = tc.get("/api/receipts").json()
    assert 0 < len(recs) < 200
    assert recs[-1]["step"] == "state"

