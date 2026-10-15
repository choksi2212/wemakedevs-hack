"""Agent tests — LLM seam (DB-free) + investigator loop on the REAL engine."""
from __future__ import annotations

import json
import os
from datetime import datetime

import httpx
import openai
import pytest

from tests.conftest import make_live_port, requires_engine, requires_sample, drop_graph
from sever.agent.investigator import Investigator, TriageReport

from sever.agent.llm import LLM, OfflineNarrator, OpenAICompatLLM, ResilientLLM, build_llm
from sever.core.jewels import DEFAULT_HOP_CAP
from sever.core.port import GraphPort
from sever.core.scoring import interdict, rank_cut_candidates
from sever.findings.stream import Finding

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
ALICE = "S-1-5-21-t-1101"
TIER1 = "S-1-5-21-t-2202"
DA = "S-1-5-21-t-t-512"  # ends -512 -> crown jewel by node id


class ExplodingLLM(LLM):
    """Worst-case LLM seam: the provider times out / dies mid-narration."""

    name = "exploding"

    def complete(self, system: str, user: str) -> str:
        raise TimeoutError("llm timeout mid-narration")


# ---- LLM seam (DB-free) ----


def test_build_llm_defaults_to_offline_without_env(monkeypatch):
    for var in ("SEVER_LLM_BASE_URL", "SEVER_LLM_API_KEY", "SEVER_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    assert isinstance(build_llm(), OfflineNarrator)


def test_build_llm_env_seam_is_resilient_and_uses_env_model(monkeypatch):
    pytest.importorskip("openai", reason="LLM-seam wiring test needs the optional agent extra (openai)")
    monkeypatch.setenv("SEVER_LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("SEVER_LLM_API_KEY", "k-test")
    monkeypatch.setenv("SEVER_LLM_MODEL", "test-model")
    llm = build_llm()
    # the live narrator is wrapped in the degrade-to-offline seam: a DEAD key
    # cannot be detected at construction (the OpenAI client does no I/O until
    # the first request), so the seam — not the env check — is what keeps the
    # agent loop alive when the provider rejects credentials.
    assert isinstance(llm, ResilientLLM)
    assert isinstance(llm._live, OpenAICompatLLM)
    assert llm._live._model == "test-model"
    assert llm.name == "openai-compat:test-model"
    assert llm.degraded is False


def test_offline_narrator_is_deterministic():
    assert OfflineNarrator().complete("s", "u") == OfflineNarrator().complete("s", "u") == ""


# ---- the human gate: exact-True contract (DB-free) ----

# Every value here is truthy or approval-LOOKING but is not the bool True.
# The gate (``is not True`` identity check) must reject all of them BEFORE
# the port is touched — which is why these tests need no engine.
NON_TRUE_APPROVALS = [
    None,
    False,
    0,
    1,
    1.0,
    "1",
    "true",
    "True",
    "yes",
    "y",
    [True],
    {"approved": True},
    (True,),
]


@pytest.mark.parametrize("bad", NON_TRUE_APPROVALS, ids=repr)
def test_gate_rejects_every_non_true_value(bad):
    inv = Investigator(port=None)  # port=None proves the gate fires first
    with pytest.raises(ValueError, match="explicit human approval"):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=bad)


def test_gate_rejects_sneaky_truthy_types():
    class EvilInt(int):
        """Equal to True (== True) but not the True singleton."""

    class AlwaysYes:
        def __bool__(self) -> bool:
            return True

    inv = Investigator(port=None)
    for bad in (EvilInt(1), AlwaysYes()):
        with pytest.raises(ValueError, match="explicit human approval"):
            inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=bad)


def test_gate_passes_only_on_exact_true():
    inv = Investigator(port=None)
    # The bool True passes the gate and PROCEEDS to the port — with port=None
    # the AttributeError is the proof execution went past the gate check.
    with pytest.raises(AttributeError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=True)
    with pytest.raises(AttributeError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL")  # default is True
    # the gate never mutated anything on the way
    assert inv.case_log == []


# ---- case_log: everything the investigator appends is JSON-serializable ----


def _snapshot_like(reachability: int, owned: list[str], jewels: list[str], nodes: int, edges: int):
    """The exact shape of scoring.snapshot() — ints and str lists only."""
    return {
        "reachability": reachability, "owned": owned, "jewels": jewels,
        "nodes": nodes, "edges": edges,
    }


def test_triage_case_log_entry_is_json_serializable():
    # Exactly what Investigator.triage appends to case_log: report.as_dict().
    report = TriageReport(
        finding=Finding("F-1", "credential_breach", ALICE),
        applied=True,
        before=_snapshot_like(1, [ALICE], [DA], 3, 2),
        after=_snapshot_like(2, [ALICE], [DA], 3, 3),
        narration_technique="T1078.002 Valid Accounts: Domain Accounts",
        narration="Compromised domain credentials confirmed.",
        paths_for_subject=[[(ALICE, "GENERIC_ALL", TIER1)], [(TIER1, "MEMBER_OF", DA)]],
        proposal=rank_cut_candidates(
            {(ALICE, "GENERIC_ALL", TIER1): 2, (TIER1, "MEMBER_OF", DA): 1}, limit=3
        ),
    )
    entry = report.as_dict()
    # strict round-trip: plain json.dumps with NO default= crutch
    assert json.loads(json.dumps(entry)) == entry
    # raw hop tuples never enter the ledger — only their count
    assert entry["paths"] == 2
    assert entry["proposal"] == [
        {"src": ALICE, "rel": "GENERIC_ALL", "dst": TIER1, "paths_on": 2},
        {"src": TIER1, "rel": "MEMBER_OF", "dst": DA, "paths_on": 1},
    ]


def test_cut_case_log_entry_is_json_serializable():
    # Exactly what Investigator.approve_and_cut appends: {"cut": receipt},
    # where receipt is scoring.interdict()'s return plus approved_by/approved_at
    # (see sever/core/scoring.py::interdict). The real receipt is pinned
    # end-to-end on the live engine in test_approved_cut_collapses_and_receipts.
    receipt = {
        "cut": {"src": ALICE, "dst": TIER1, "rel": "GENERIC_ALL", "relationships_removed": 1},
        "before": _snapshot_like(1, [ALICE], [DA], 3, 2),
        "after": _snapshot_like(0, [], [DA], 3, 1),
        "requery_ms": 0.83,
        "verdict": "collapsed",
        "approved_by": "on-call-analyst",
        "approved_at": "2026-10-15T15:00:00",
    }
    entry = {"cut": receipt}
    assert json.loads(json.dumps(entry)) == entry


# ---- investigator on the live engine ----


def _tiny_estate(port):
    """Minimal estate on the real engine: alice -GENERIC_ALL-> tier1 -> DA."""
    port.graph.query(
        "CREATE (:User {objectid: $a, name: 'alice', owned: false}), "
        "(:Group {objectid: $g, name: 'tier1'}), "
        "(:Group {objectid: $da, name: 'domain admins'})",
        {"a": ALICE, "g": TIER1, "da": DA},
    )
    port.graph.query(
        "MATCH (a:User {objectid: $a}), (g:Group {objectid: $g}) CREATE (a)-[:GENERIC_ALL]->(g)",
        {"a": ALICE, "g": TIER1},
    )
    port.graph.query(
        "MATCH (g1:Group {objectid: $g}), (g2:Group {objectid: $da}) CREATE (g1)-[:MEMBER_OF]->(g2)",
        {"g": TIER1, "da": DA},
    )


@pytest.fixture()
def tiny_port():
    from sever.core.falkor_port import FalkorGraphPort

    name = "sever_test_agent_tiny"
    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=name,
    )
    drop_graph(port, name)
    _tiny_estate(port)
    yield port
    drop_graph(port, name)


@requires_engine
def test_triage_marks_breach_owned_and_proposes(tiny_port):
    from sever.findings.stream import Finding

    inv = Investigator(tiny_port)
    report = inv.triage(Finding("F-1", "credential_breach", ALICE))
    assert report.after["owned"] == [ALICE]
    assert report.after["reachability"] == 1
    assert report.paths_for_subject  # alice -> tier1 -> DA
    assert report.proposal
    top = report.proposal[0]
    assert (top["src"], top["rel"]) in {(ALICE, "GENERIC_ALL"), (TIER1, "MEMBER_OF")}


@requires_engine
def test_llm_timeout_mid_narration_never_breaks_triage(tiny_port):
    # The garnish call is best-effort: when the LLM dies mid-narration the
    # finding flow must still complete with the deterministic ATT&CK template —
    # the graph mutation (apply/mark_owned) has already happened by then.
    inv = Investigator(tiny_port, llm=ExplodingLLM())
    report = inv.triage(Finding("F-1", "credential_breach", ALICE))
    assert report.after["owned"] == [ALICE]
    assert report.narration_technique == "T1078.002 Valid Accounts: Domain Accounts"
    assert report.narration  # template narration carries the finding
    assert report.proposal  # and the interdiction proposal still lands


@requires_engine
def test_human_gate_blocks_unapproved_cuts(tiny_port):
    inv = Investigator(tiny_port)
    from sever.findings.stream import Finding

    inv.triage(Finding("F-1", "credential_breach", ALICE))
    with pytest.raises(ValueError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval=False)
    with pytest.raises(ValueError):
        inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", require_explicit_approval="yolo")


@requires_engine
def test_approved_cut_collapses_and_receipts(tiny_port):
    inv = Investigator(tiny_port)
    from sever.findings.stream import Finding

    inv.triage(Finding("F-1", "credential_breach", ALICE))
    receipt = inv.approve_and_cut(ALICE, TIER1, "GENERIC_ALL", approved_by="manas")
    assert receipt["approved_by"] == "manas"
    assert receipt["before"]["reachability"] == 1
    assert receipt["after"]["reachability"] == 0
    assert receipt["verdict"] == "collapsed"
    assert receipt["requery_ms"] is not None
    assert any("cut" in entry for entry in inv.case_log)
    # the REAL receipt and the WHOLE ledger (triage + cut entries) are
    # strictly JSON-serializable — the receipts trail is plain JSON
    assert json.loads(json.dumps(receipt)) == receipt
    assert json.loads(json.dumps(inv.case_log)) == inv.case_log


@requires_engine
@requires_sample
def test_investigator_end_to_end_on_sample():
    port = make_live_port("sever_test_agent_sample")
    try:
        from sever.findings.stream import Finding

        inv = Investigator(port, llm=OfflineNarrator())
        report = inv.triage(Finding("F-1", "credential_breach", HERO))
        assert report.after["reachability"] == 1
        assert report.proposal[0]["paths_on"] >= 5
        cut = report.proposal[0]
        receipt = inv.approve_and_cut(cut["src"], cut["dst"], cut["rel"])
        assert receipt["after"]["reachability"] == 0
        assert receipt["verdict"] == "collapsed"
    finally:
        drop_graph(port, "sever_test_agent_sample")


# ---------------------------------------------------------------------------
# Agent-loop guards (DB-free): ranking determinism, LLM-failure isolation,
# verdict honesty, and case-ledger completeness.
# ---------------------------------------------------------------------------


class FakeGraphPort(GraphPort):
    """In-memory port — the loop's graph semantics with no engine at all."""

    def __init__(self, jewels: tuple[str, ...] = ()) -> None:
        self._edges: list[tuple[str, str, str]] = []  # (src, rel, dst)
        self._owned: set[str] = set()
        self._jewels: set[str] = set(jewels)

    def load(self, graph) -> None:  # pragma: no cover - unused in these tests
        raise NotImplementedError

    def node_count(self) -> int:
        ids = {n for e in self._edges for n in (e[0], e[2])}
        return len(ids | self._owned | self._jewels)

    def edge_count(self) -> int:
        return len(self._edges)

    def mark_owned(self, objectid: str) -> None:
        self._owned.add(objectid)

    def owned_ids(self) -> list[str]:
        return sorted(self._owned)

    def crown_jewels(self) -> list[str]:
        return sorted(self._jewels)

    def _shortest(self, src: str, dst: str, hop_cap: int):
        from collections import deque

        queue = deque([(src, [])])
        seen = {src}
        while queue:
            node, hops = queue.popleft()
            if node == dst:
                return hops
            if len(hops) >= hop_cap:
                continue
            for s, rel, d in self._edges:
                if s == node and d not in seen:
                    seen.add(d)
                    queue.append((d, hops + [(s, rel, d)]))
        return None

    def paths_to_jewels(self, objectid: str, hop_cap: int = DEFAULT_HOP_CAP, ties: bool = False):
        paths = []
        for jewel in self.crown_jewels():
            hops = self._shortest(objectid, jewel, hop_cap)
            if hops:
                paths.append(hops)
        return paths

    def reachability(self, hop_cap: int = DEFAULT_HOP_CAP) -> int:
        return sum(1 for o in self.owned_ids() if self.paths_to_jewels(o, hop_cap))

    def edge_frequency(self, hop_cap: int = DEFAULT_HOP_CAP):
        freq: dict[tuple[str, str, str], int] = {}
        for owned in self.owned_ids():
            for path in self.paths_to_jewels(owned, hop_cap):
                for hop in path:
                    freq[hop] = freq.get(hop, 0) + 1
        return freq

    def add_edge(self, src: str, dst: str, rel: str, props=None) -> bool:
        edge = (src, rel, dst)
        if edge in self._edges:
            return False
        self._edges.append(edge)
        return True

    def cut(self, src: str, dst: str, rel: str) -> int:
        edge = (src, rel, dst)
        n = self._edges.count(edge)
        self._edges = [e for e in self._edges if e != edge]
        return n

    def profile(self, query: str, params=None) -> str:
        return "fake-graph-profile"

    def receipt(self) -> dict:
        return {
            "backend": "fake",
            "graph": "fake",
            "nodes": self.node_count(),
            "edges": self.edge_count(),
            "owned": self.owned_ids(),
            "crown_jewels": self.crown_jewels(),
            "reachability": self.reachability(),
        }


def _tiny_port() -> FakeGraphPort:
    port = FakeGraphPort(jewels=(DA,))
    port._edges = [(ALICE, "GENERIC_ALL", TIER1), (TIER1, "MEMBER_OF", DA)]
    return port


# ---- propose()/ranking: equal-frequency ties are a deterministic total order ----


def test_rank_cut_candidates_breaks_ties_deterministically():
    freq = {
        (TIER1, "MEMBER_OF", DA): 2,                    # three-way tie ...
        (ALICE, "GENERIC_ALL", TIER1): 2,               # ... on count 2 ...
        ("S-1-5-21-t-3303", "OWNS", DA): 2,             # ... plus a clear winner
        (ALICE, "WRITE_DACL", TIER1): 5,
    }
    ranked = rank_cut_candidates(freq, limit=10)
    assert [c["paths_on"] for c in ranked] == [5, 2, 2, 2]
    # ties fall back to lexicographic (src, rel, dst) — a full total order
    tied = [(c["src"], c["rel"], c["dst"]) for c in ranked[1:]]
    assert tied == sorted(tied)
    # replay-identical: same input, same ranking — every time
    assert rank_cut_candidates(freq, limit=10) == ranked


def test_propose_is_replay_identical_on_a_tie_heavy_graph():
    inv = Investigator(_tiny_port())
    inv.triage(Finding("F-1", "credential_breach", ALICE))
    # both edges sit on the single owned->jewel path: a 1/1 frequency tie
    assert inv.propose() == inv.propose()
    assert inv.propose(limit=3) == inv.propose(limit=3)


# ---- triage isolation: an LLM failure mid-triage can never abort the loop ----


class _DeadKeyLLM(LLM):
    """Live narrator whose provider rejects the key at request time — the
    exact failure mode a WRONG SEVER_LLM_API_KEY produces: construction
    succeeds (no I/O), complete() raises."""

    def __init__(self) -> None:
        self.calls = 0
        self.name = "openai-compat:dead-key"

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        resp = httpx.Response(
            401, request=httpx.Request("POST", "https://api.test/v1/chat/completions")
        )
        raise openai.AuthenticationError("Invalid API key provided", response=resp, body=None)


def test_triage_survives_dead_key_and_still_reports_before_after():
    port = _tiny_port()
    dead = _DeadKeyLLM()
    inv = Investigator(port, llm=dead)
    # before the fix this RAISED: the loop died mid-triage, after the finding
    # had already been applied to the graph — no report, no ledger entry.
    report = inv.triage(Finding("F-001", "credential_breach", ALICE))
    assert report.before["owned"] == []
    assert report.after["owned"] == [ALICE]
    assert report.after["reachability"] == 1
    assert report.paths_for_subject, "paths still enumerated for the proposal"
    assert report.proposal, "the cut proposal still ranked"
    assert dead.calls == 1, "the dead narrator was consulted exactly once"
    assert len(inv.case_log) == 1, "the step is still on the ledger"


def test_resilient_llm_degrades_on_auth_failure_and_latches():
    dead = _DeadKeyLLM()
    seam = ResilientLLM(dead)
    assert seam.degraded is False
    assert seam.complete("s", "u") == "", "auth failure degrades to offline narration"
    assert seam.degraded is True
    assert dead.calls == 1, "the failing live narrator was touched exactly once"
    assert seam.complete("s", "u") == ""
    assert dead.calls == 1, "a dead provider is never retried — offline from here on"


def test_build_llm_dead_key_degrades_to_offline_narration(monkeypatch):
    """A deliberately wrong SEVER_LLM_API_KEY: build_llm must still yield a
    seam that NEVER crashes the loop — degrading on the provider's 401 the
    way it already degrades on missing env (live-verified on glm-5.3)."""
    monkeypatch.setenv("SEVER_LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("SEVER_LLM_API_KEY", "definitely-not-the-real-key")
    monkeypatch.setenv("SEVER_LLM_MODEL", "test-model")

    class _AuthRejectedOpenAI:
        def __init__(self, *a, **k) -> None: ...

        class chat:
            class completions:
                @staticmethod
                def create(**k):
                    resp = httpx.Response(
                        401,
                        request=httpx.Request(
                            "POST", "https://example.test/v1/chat/completions"
                        ),
                    )
                    raise openai.AuthenticationError(
                        "Invalid API key provided", response=resp, body=None
                    )

    monkeypatch.setattr(openai, "OpenAI", _AuthRejectedOpenAI)
    seam = build_llm()
    assert seam.degraded is False, "undetectable at construction — no I/O yet"
    assert (
        seam.complete(
            "You are SEVER, an on-call identity-security agent.",
            "Finding: credential_breach on S-1. One-line commentary for the on-call analyst:",
        )
        == ""
    ), "the rejected key degrades to '' instead of raising"
    assert seam.degraded is True, "the auth failure latched"


def test_live_llm_budgets_reasoning_tokens(monkeypatch):
    """glm-5.3 burns ~1020 reasoning tokens BEFORE any content — measured live:
    at max_tokens=1024 the model hit finish_reason='length' with content=''
    (silent empty garnish); at 4096 it finished with real commentary. The seam
    must request a budget no reasoning model starves on."""
    captured = {}

    class _CapturingOpenAI:
        def __init__(self, *a, **k) -> None: ...

        class chat:
            class completions:
                @staticmethod
                def create(**k):
                    captured.update(k)

                    class _Msg:
                        content = "ok"

                    class _Choice:
                        message = _Msg()
                        finish_reason = "stop"

                    class _Resp:
                        choices = [_Choice()]

                    return _Resp()

    monkeypatch.setenv("SEVER_LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("SEVER_LLM_API_KEY", "k-test")
    monkeypatch.setenv("SEVER_LLM_MODEL", "glm-5.3")
    monkeypatch.setattr(openai, "OpenAI", _CapturingOpenAI)
    seam = build_llm()
    assert seam.complete("s", "u") == "ok"
    assert captured["max_tokens"] >= 4096, "reasoning-token budget must cover glm-5.3 chains"


# ---- verdict honesty: 'collapsed' is only ever claimed with measured proof ----


def test_interdict_verdicts_are_measured_only():
    port = _tiny_port()
    port.mark_owned(ALICE)
    port.add_edge(ALICE, "S-1-5-21-t-3303", "WRITE_OWNER")  # off-path noise edge

    # a cut off every attack path: surface degraded, reachability unchanged
    noise = interdict(port, ALICE, "S-1-5-21-t-3303", "WRITE_OWNER")
    assert noise["cut"]["relationships_removed"] == 1
    assert noise["before"]["reachability"] == noise["after"]["reachability"] == 1
    assert noise["verdict"] == "degraded"

    # a cut that measurably drops reachability: the ONLY 'collapsed' claim
    bridge = interdict(port, TIER1, DA, "MEMBER_OF")
    assert bridge["before"]["reachability"] == 1
    assert bridge["after"]["reachability"] == 0
    assert bridge["verdict"] == "collapsed"

    # a cut on an edge that does not exist: 0 removed -> 'no_effect', nothing claimed
    ghost = interdict(port, ALICE, "S-1-5-21-t-9999", "GENERIC_ALL")
    assert ghost["cut"]["relationships_removed"] == 0
    assert ghost["before"] == ghost["after"]
    assert ghost["verdict"] == "no_effect"


def test_approve_and_cut_allows_human_override_of_ranking():
    """The human IS the authority: approve_and_cut executes any edge the human
    explicitly approves, not only the top-ranked proposal — the ranking is a
    proposal, never a permission check."""
    port = _tiny_port()
    inv = Investigator(port)
    inv.triage(Finding("F-1", "credential_breach", ALICE))
    proposal = inv.propose()
    non_top = proposal[-1]  # the other tie edge — explicitly NOT top-ranked
    receipt = inv.approve_and_cut(
        non_top["src"], non_top["dst"], non_top["rel"], approved_by="human-override"
    )
    assert receipt["cut"]["relationships_removed"] == 1
    assert receipt["before"]["reachability"] == 1
    assert receipt["after"]["reachability"] == 0
    assert receipt["verdict"] == "collapsed", "honest re-measured receipt"
    assert port.reachability() == 0


# ---- case-ledger completeness: every step stamped, ids unique, ISO timestamps ----


def _iso_utc(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts)  # raises on a non-ISO stamp
    assert parsed.tzinfo is not None, "timestamps must carry a timezone offset"
    return parsed


def test_case_log_ledger_is_complete_after_a_full_loop():
    port = _tiny_port()
    inv = Investigator(port, llm=OfflineNarrator())
    inv.triage(Finding("F-001", "credential_breach", ALICE))
    inv.triage(Finding("F-002", "kerberoastable_spn", ALICE))
    proposal = inv.propose()
    inv.approve_and_cut(
        proposal[0]["src"], proposal[0]["dst"], proposal[0]["rel"], approved_by="auditor"
    )
    entries = inv.case_log
    assert len(entries) == 3

    # every step: a unique sequential id and an ISO-8601 timestamp with offset
    assert [e["step"] for e in entries] == [1, 2, 3]
    stamps = [_iso_utc(e["ts"]) for e in entries]
    assert stamps == sorted(stamps), "ledger timestamps are monotonic"
    finding_ids = [e["finding"] for e in entries if "finding" in e]
    assert finding_ids == ["F-001", "F-002"], "finding ids present and unique"

    # required fields per entry type
    for triage in entries[:2]:
        for key in ("finding", "kind", "applied", "before", "after",
                    "technique", "narration", "paths", "proposal"):
            assert key in triage, f"triage entry missing {key}"
    receipt = entries[2]["cut"]  # the ledger nests the full interdict receipt
    for key in ("cut", "before", "after", "requery_ms", "verdict",
                "approved_by", "approved_at"):
        assert key in receipt, f"cut receipt missing {key}"
    assert _iso_utc(receipt["approved_at"])  # approval stamp is ISO too

    # and the stamped ledger is still plain JSON
    assert json.loads(json.dumps(entries)) == entries
