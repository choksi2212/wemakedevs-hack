"""audit5/incident-verify: pin the socket-timeout env plumbing (53fa606 + bfe9308).

The incident chain: engine latency spikes dragged requests until the proxy cut
them into EMPTY bodies; the fix bounds hangs with redis-py socket timeouts
(SEVER_FALKOR_SOCKET_TIMEOUT / SEVER_FALKOR_CONNECT_TIMEOUT -> FalkorDB client
kwargs, defaults 30/10). The DB-free suite stubs the client, which is exactly
why the patch could ship without `import os` and pass every test — only a REAL
boot (the Render deploy) hit the NameError (update_failed, ~08:25 IST).

This test builds the REAL constructor path with a fake ``falkordb`` module
injected into sys.modules — no engine, no network — and asserts the env
values actually reach the client, the defaults hold, and a missing ``import
os`` would fail HERE, not on the next deploy.
"""
from __future__ import annotations

import sys
import types

import pytest

from sever.core import falkor_port

GRAPH = "sever_audit5_iv_plumb"


class _FakeGraph:
    def __init__(self, name: str) -> None:
        self.name = name


def build_port(monkeypatch, env: dict[str, str]):
    """Construct FalkorGraphPort with a fake falkordb module; return (port, captured kwargs)."""
    capture: dict[str, object] = {}

    class FakeFalkorDB:
        def __init__(self, **kwargs) -> None:
            capture.update(kwargs)
            self._graph = _FakeGraph(GRAPH)

        def select_graph(self, name: str) -> _FakeGraph:
            self._graph.name = name
            return self._graph

    fake_mod = types.ModuleType("falkordb")
    fake_mod.FalkorDB = FakeFalkorDB
    # the lazy `from falkordb import FalkorDB` in FalkorGraphPort.__init__
    # consults sys.modules first, so this works whether or not the real lib
    # is installed — and no real connection is ever attempted.
    monkeypatch.setitem(sys.modules, "falkordb", fake_mod)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    for key in ("SEVER_FALKOR_SOCKET_TIMEOUT", "SEVER_FALKOR_CONNECT_TIMEOUT"):
        if key not in env:
            monkeypatch.delenv(key, raising=False)
    port = falkor_port.FalkorGraphPort(host="engine", port=6379, graph_name=GRAPH)
    return port, capture


def test_env_values_reach_the_falkordb_client(monkeypatch):
    port, capture = build_port(monkeypatch, {
        "SEVER_FALKOR_SOCKET_TIMEOUT": "7",
        "SEVER_FALKOR_CONNECT_TIMEOUT": "4",
    })
    assert capture["socket_timeout"] == 7
    assert capture["socket_connect_timeout"] == 4
    assert capture["host"] == "engine"
    assert capture["port"] == 6379
    assert capture["username"] is None
    assert capture["password"] is None
    assert port.graph_name == GRAPH


def test_defaults_bound_hangs_at_30s_socket_and_10s_connect(monkeypatch):
    _, capture = build_port(monkeypatch, {})
    # defaults from falkor_port: a stalled query fails in <= 30s as a clean
    # ConnectionError -> 503 JSON; a dead engine refuses to connect in <= 10s.
    assert capture["socket_timeout"] == 30
    assert capture["socket_connect_timeout"] == 10


def test_non_default_env_does_not_raise_nameerror(monkeypatch):
    """bfe9308 regression: `os.environ.get` runs on this exact path; a dropped
    `import os` explodes here (NameError) instead of on the next real boot."""
    try:
        _, capture = build_port(monkeypatch, {"SEVER_FALKOR_SOCKET_TIMEOUT": "11"})
    except NameError as e:  # pragma: no cover — the fix under test prevents this
        pytest.fail(f"missing-import regression reintroduced: {e}")
    assert capture["socket_timeout"] == 11
