"""audit8/fix-code — boot-time outage containment + entry-guard pins.

F303 (medium, quickstart): the README §8 console command crashed at import
with a raw redis traceback when no engine was reachable (fresh-clone
verified against main a4f7706 with SEVER_FALKOR_PORT=6390 — nothing
listening — and with a non-FalkorDB RESP server on 6379). The product
documents "engine-down containment" (§8) and "engine outages -> 503 JSON"
(§11) as its contracts; a process that dies before uvicorn binds honors
neither, and the free-tier Cloud instance stopping after an idle day meant
a crash-loop, not containment.

These pins hold the fix: the console ALWAYS binds (the production
``build_app()`` path against a real dead socket AND the injected-port
resilience lane), every engine-touching request answers through the
registered 503 JSON lane, the failed boot attempt lands on the receipts
ledger with ``outcome: unknown`` — and a NON-outage boot error (a
configuration problem) still fails loud, never silently half-boots.

F309 (low, quickstart): ``python -m sever.eval.ablation`` with the engine
down prints ONE actionable line and exits 2 instead of dumping a raw redis
traceback (the same guard belongs at the entry of every beat script;
scripts/ is outside this lane — this pins the sever.eval entry the module
owns).
"""
from __future__ import annotations

import json

import pytest

GRAPH = "sever_audit8_fixcode_boot"


def _conn_refused():
    """The exact exception class a dead engine raises (redis-py via falkordb)."""
    from redis.exceptions import ConnectionError

    return ConnectionError(
        "Error 10061 connecting to 127.0.0.1:6390. No connection could be "
        "made because the target machine actively refused it."
    )


@pytest.fixture()
def boot_env(tmp_path, monkeypatch):
    """Isolated ledger dir + a dead engine port, mirroring the resilience
    suite's fixture discipline."""
    monkeypatch.chdir(tmp_path)  # CaseLog root lands in the tmp dir
    monkeypatch.setenv("SEVER_CONSOLE_NO_BOOTSTRAP", "1")
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", GRAPH)
    monkeypatch.setenv("SEVER_FALKOR_PORT", "6390")  # nothing listens here
    import sever.console.app as appmod

    appmod._fold_cache.clear()
    yield appmod
    appmod._fold_cache.clear()


class _DeadAtBootPort:
    """A port whose estate probe dies with the real outage class at boot —
    the injected-port lane of the F303 scenario (same shape the resilience
    suite uses). Every engine touch raises the outage, so post-boot
    requests must surface the 503 lane, never an AttributeError 500."""

    graph_name = GRAPH

    def __init__(self) -> None:
        self.graph = type("G", (), {})()  # no query attr -> folded paths decline

    def _raise(self) -> None:
        raise _conn_refused()

    def load(self, graph) -> None:
        self._raise()

    def node_count(self) -> int:
        self._raise()

    def edge_count(self) -> int:
        self._raise()

    def mark_owned(self, objectid: str) -> None:
        self._raise()

    def owned_ids(self) -> list[str]:
        self._raise()

    def crown_jewels(self) -> list[str]:
        self._raise()

    def reachability(self, hop_cap: int = 12) -> int:
        self._raise()

    def paths_to_jewels(self, objectid: str, hop_cap: int = 12,
                        ties: bool = False):
        self._raise()

    def edge_frequency(self, hop_cap: int = 12):
        self._raise()


def _ledger_events(tmp_path):
    path = tmp_path / "out" / "cases" / f"{GRAPH}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# F303 — the console binds and contains; the ledger carries the attempt
# ---------------------------------------------------------------------------

def test_production_boot_against_a_real_dead_socket_binds(boot_env, tmp_path):
    """The exact judge scenario: ``uvicorn sever.console.app:app`` imports
    the module, the module builds the app, the engine probe finds nothing
    listening. Pre-fix this raised; the fix must return a serving app."""
    from fastapi.testclient import TestClient

    app = boot_env.build_app()  # port=None -> real FalkorGraphPort on :6390
    tc = TestClient(app)

    r = tc.get("/api/state")
    assert r.status_code == 503, r.text
    assert r.json()["detail"].startswith("engine unreachable")
    r = tc.get("/api/health")
    assert r.status_code == 503, r.text

    events = _ledger_events(tmp_path)
    boot_failures = [e for e in events if e.get("step") == "console_boot_failed"]
    assert boot_failures, "the failed boot must be on the receipts trail"
    assert boot_failures[0]["outcome"] == "unknown"
    assert "ConnectionError" in boot_failures[0]["error"]
    # no success was invented anywhere on the trail
    assert not [e for e in events if e.get("step") == "estate_loaded"]


def test_injected_dead_port_boots_and_serves_503s(boot_env, tmp_path):
    from fastapi.testclient import TestClient

    app = boot_env.build_app(port=_DeadAtBootPort())
    tc = TestClient(app)
    r = tc.get("/api/state")
    assert r.status_code == 503
    assert r.json()["detail"].startswith("engine unreachable")
    assert _ledger_events(tmp_path), "the boot failure is receipted"


def test_non_outage_boot_errors_still_fail_loud(boot_env):
    """A configuration error (not an engine outage) must never be contained
    into a silent partial boot — e.g. a corrupt sample dir raises its own
    exception type straight out of build_app."""
    class _ConfigBrokenPort:
        graph_name = GRAPH
        graph = type("G", (), {})()

        def node_count(self) -> int:
            raise ValueError("SEVER_SAMPLE_DIR points at a corrupt dump")

    with pytest.raises(ValueError, match="corrupt dump"):
        boot_env.build_app(port=_ConfigBrokenPort())


# ---------------------------------------------------------------------------
# F309 — sever.eval.ablation entry guard
# ---------------------------------------------------------------------------

def test_ablation_entry_guard_prints_one_actionable_line_and_exits_2(
        boot_env, capsys):
    from sever.eval.ablation import main

    rc = main(out_path="out/should_never_be_written.json")
    assert rc == 2, "the guard exits 2 (distinct from a measurement failure)"
    out = capsys.readouterr().out
    assert "docker compose up -d" in out
    assert "(ConnectionError)" in out, "the cause class is named"
    import os

    assert not os.path.exists("out/should_never_be_written.json"), (
        "no receipt is attempted when the engine is unreachable"
    )
