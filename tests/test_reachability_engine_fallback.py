"""audit8/fix-code — F900 production regression pins: engine-version fallback.

Production evidence (deployed Cloud 4.22.0, dep-db94uvek, develop b6dae5a):
/api/state answered reach 0 and /api/paths answered [] WITH an owned
principal, while ryzen 6.0.0 was green on the same code. Root cause: the
fleet-7 arm forms (all-owned AND $oid-bound per-owned cross-product
WITH-shortestPath) are not evaluated correctly on engines < falkordb 6.0.0
for this estate shape; the legacy per-pair forms (both endpoints
$param-bound) are the only family production proved there — reach 0->1
verified repeatedly pre-fleet-7, and the plan endpoint's per-pair
enumeration kept answering base_reachability=1 through the whole outage.

These pins hold the fix on a REAL engine (the same engine the fold suite
runs on, 6.0.0): forcing the port's version probe to the Cloud family
(42200) must select the per-pair fallback and answer EXACTLY what the
modern-arm path answers on the same estate — reachability, paths, and the
console's /api/state and /api/paths responses, byte-identical. A port
without the probe attribute (every engine-free fake) is conservatively
gated off the arm folds.
"""
from __future__ import annotations

import pytest

from tests.conftest import (
    drop_graph,
    make_live_port,
    prefixed,
    requires_engine,
    requires_sample,
)

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
GRAPH = prefixed("sever_audit8_fixcode_f900")

pytestmark = [requires_engine, requires_sample]


@pytest.fixture(scope="module")
def port():
    p = make_live_port(GRAPH)
    p.mark_owned(HERO)  # the breach: the exact production shape
    yield p
    drop_graph(p, GRAPH)


@pytest.fixture()
def forced_old(port):
    """Force the Cloud 4.22.0 engine family on the port's cached probe."""
    assert port.reachability() >= 1, "the armed estate must have a breach"
    port._engine_graph_ver = 42200  # managed Cloud family
    assert port._modern_engine is False
    yield port
    port._engine_graph_ver = None  # re-probe from the real engine


def test_forced_old_engine_reachability_equals_per_pair_reference(forced_old):
    from sever.core.falkor_port import REACHABILITY_QUERY_TEMPLATE
    from sever.core.jewels import DEFAULT_HOP_CAP, cypher_traversal_pattern

    port = forced_old
    modern = None
    # per-pair existence reference, computed directly on the engine
    probe = REACHABILITY_QUERY_TEMPLATE.format(
        pattern=cypher_traversal_pattern(DEFAULT_HOP_CAP))
    reached = set()
    for principal in sorted(port.owned_ids()):
        for jewel in sorted(port.crown_jewels()):
            rows = port.graph.query(
                probe, {"oid": principal, "target": jewel}, timeout=60000).result_set
            if rows and rows[0][0]:
                reached.add(principal)
                break
    jewels = set(port.crown_jewels())
    expected = len(reached | (set(port.owned_ids()) & jewels))

    port._engine_graph_ver = None  # modern arms, for the comparison number
    modern = port.reachability()
    port._engine_graph_ver = 42200

    old_engine_answer = port.reachability()
    assert old_engine_answer == expected, (
        "the <6.0.0 fallback must equal the per-pair reference"
    )
    assert old_engine_answer == modern, (
        f"the forced-old answer ({old_engine_answer}) must equal the "
        f"modern-arm answer ({modern}) on this engine — the fallback "
        "changes the FORM, never the number"
    )


def test_forced_old_engine_paths_equal_modern_paths(forced_old):
    port = forced_old
    port._engine_graph_ver = None
    modern = port.paths_to_jewels(HERO)
    port._engine_graph_ver = 42200
    assert port.paths_to_jewels(HERO) == modern, (
        "the <6.0.0 path (legacy per-pair canonical loop) must enumerate "
        "exactly the paths the modern fold enumerates"
    )
    assert modern, "the armed estate must have paths to enumerate"


def test_console_state_and_paths_equal_under_forced_old_engine(forced_old, tmp_path,
                                                               monkeypatch):
    """The console's /api/state and /api/paths must answer byte-identically
    with the arms gated off (old-engine fallback) and with the arms on —
    the F900 production scenario answered 0/[] where the slow path was
    always right."""
    import sever.console.app as appmod

    monkeypatch.chdir(tmp_path)  # CaseLog root lands in the tmp dir
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", GRAPH)
    app = appmod.build_app(port=forced_old)
    from fastapi.testclient import TestClient

    tc = TestClient(app)

    forced_old._engine_graph_ver = 42200
    state_old = tc.get("/api/state").json()
    paths_old = tc.get("/api/paths").json()

    forced_old._engine_graph_ver = None
    state_modern = tc.get("/api/state").json()
    paths_modern = tc.get("/api/paths").json()

    assert state_old == state_modern, (
        "old-engine /api/state must equal the modern fold's answer — "
        f"got old={state_old.get('reachability')} vs "
        f"modern={state_modern.get('reachability')}"
    )
    assert paths_old == paths_modern, "old-engine /api/paths must match"
    assert state_old["reachability"] >= 1, (
        "the F900 production regression: reachability must see the breach"
    )
    assert paths_old["paths"], "the F900 production regression: paths must fill"


def test_arms_ok_is_conservative_for_ports_without_the_probe():
    from sever.console.app import _arms_ok

    class _NoProbe:
        pass

    class _ModernProbe:
        @property
        def _modern_engine(self) -> bool:
            return True

    assert _arms_ok(_NoProbe()) is False, (
        "engine-free fake ports must never run the arm folds"
    )
    assert _arms_ok(_ModernProbe()) is True
