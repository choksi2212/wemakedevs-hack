"""audit8/fix-code + audit C1 — F900 production regression pins: engine-version fallback.

Production evidence (deployed Cloud 4.22.0, dep-db94uvek, develop b6dae5a):
/api/state answered reach 0 and /api/paths answered [] WITH an owned
principal, while ryzen 6.0.0 was green on the same code. Root cause: the
fleet-7 arm forms (the $oid-bound per-owned cross-product
WITH-shortestPath arms) answer nothing on engines < falkordb 6.0.0 for
this estate shape — production answered reach 0 with an owned principal
on TWO deploys. The pre-fleet-7 two-arm form ran green on that Cloud
estate for days in the SINGLE-OWNED demo shape (reach 0->1 verified
repeatedly), but the repo's own receipt
(docs/receipts/perf_audit7_client_roundtrips.json,
engine_finding_4_22_0_cross_shortestpath_bug) measured the all-owned
cross-product arm returning ZERO rows for 2 owned principals (one
reaching) on the deployed Cloud 4.22.0 where the per-pair existence
probe sees one — so reachability() now runs the PER-PAIR EXISTENCE LOOP
(REACHABILITY_QUERY_TEMPLATE, both endpoints $param-bound, a principal
counted at its first hit) on every engine the version probe does not
vouch for (audit C1), and the per-pair canonical loop for paths.

These pins hold the fix on a REAL engine (the same engine the fold suite
runs on, 6.0.0) with the MEASURED FAILURE SHAPE constructed: TWO owned
principals, exactly one of which reaches a crown jewel — the shape the
receipt measured the cross-product arm undercounting to 0. Forcing the
port's version probe to the Cloud family (42200) must select the per-pair
fallback (existence probe for reachability + per-pair canonical paths)
and answer EXACTLY what the modern-arm path answers on the same estate —
reachability, paths, and the console's /api/state and /api/paths
responses, byte-identical.

HONEST BOUNDARY (audit H20): the forced-old engine here is 6.0.0 wearing
a faked version label, and BOTH query forms evaluate correctly on it —
so the old==modern equality below is a tautology about THIS engine's
evaluation semantics and can never reproduce the receipted 4.22.0
shortestPath-undercount behavior itself. What the forced-label pin DOES
prove is FORM SELECTION: the gate routes unvouched engines to the
per-pair existence loop (asserted on the issued query texts, never on
the arms), the form the F900 reopen's raw wire test re-proved against
the live Cloud. Only a live pin against a real 4.22.0 engine (the
managed Cloud, or its docker image) could prove the old-dialect
evaluation itself; everything else must stay honest about that. A port
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
# the second owned principal: an ISOLATED node that cannot reach any
# crown jewel — with HERO this constructs the receipted failure shape
# (2 owned principals, exactly one reaching)
NO_REACH = "S-1-5-21-900-audit8-noreach"
GRAPH = prefixed("sever_audit8_fixcode_f900")

pytestmark = [requires_engine, requires_sample]


@pytest.fixture(scope="module")
def port():
    p = make_live_port(GRAPH)
    p.mark_owned(HERO)  # the breach: the exact production shape
    # audit C1/H20: construct the MEASURED failure shape — a SECOND owned
    # principal that cannot reach any crown jewel (an isolated node), so
    # the estate carries 2 owned principals with exactly one reaching:
    # the shape the receipt measured the all-owned arm returning 0 rows
    # for on the deployed Cloud 4.22.0 (where the per-pair probe sees 1).
    p.graph.query(
        "CREATE (u:User {objectid: $oid, name: $name})",
        {"oid": NO_REACH, "name": "audit8-noreach"},
    )
    p.mark_owned(NO_REACH)
    assert len(p.owned_ids()) == 2, "the measured failure shape needs >= 2 owned"
    assert p.reachability() == 1, "exactly ONE of the two owned principals reaches"
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

    # the measured failure shape is really constructed (2 owned, the
    # isolated second principal must NOT reach)
    assert len(port.owned_ids()) == 2
    assert HERO in reached, "the hero must reach a crown jewel"
    assert NO_REACH not in reached, (
        "the isolated second owned principal must not reach — this is the "
        "2-owned/one-reaching shape the receipt measured"
    )

    # FORM SELECTION (the honest content of a forced-label pin on a 6.0.0
    # engine): forced-old reachability must issue the per-pair existence
    # probe and NEVER the cross-product arm forms
    port.rt_reset()
    old_engine_answer = port.reachability()
    queries = port.rt_receipt()["queries"]
    assert any("MATCH (o {objectid: $oid}), (t {objectid: $target})" in q
               for q in queries), (
        "the forced-old path must issue the per-pair existence probe "
        "(REACHABILITY_QUERY_TEMPLATE)"
    )
    assert not any("MATCH (o {owned: true})," in q for q in queries), (
        "the forced-old path must NOT issue the cross-product arm forms — "
        "the form the receipt measured returning 0 rows for 2 owned "
        "principals on Cloud 4.22.0 (audit C1)"
    )

    assert old_engine_answer == expected, (
        "the <6.0.0 fallback (per-pair existence loop) must equal the "
        "per-pair reference"
    )

    port._engine_graph_ver = None  # modern arms, for the comparison number
    modern = port.reachability()
    port._engine_graph_ver = 42200

    assert old_engine_answer == modern, (
        f"the forced-old answer ({old_engine_answer}) must equal the "
        f"modern-arm answer ({modern}) on this engine — the fallback "
        "changes the FORM, never the number"
    )
    assert modern >= 1, "the armed estate must have a breach"


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
    always right. The gate is captured at build_app time (one engine, one
    answer), so the two modes are exercised with two apps on the same
    port. The estate carries the 2-owned/one-reaching failure shape, so
    the old-engine leg of this comparison runs on the shape production
    actually undercounted."""
    import sever.console.app as appmod

    monkeypatch.chdir(tmp_path)  # CaseLog root lands in the tmp dir
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", GRAPH)
    from fastapi.testclient import TestClient

    forced_old._engine_graph_ver = 42200  # Cloud family at build time
    tc_old = TestClient(appmod.build_app(port=forced_old))
    state_old = tc_old.get("/api/state").json()
    paths_old = tc_old.get("/api/paths").json()

    forced_old._engine_graph_ver = None  # re-probe -> modern at build time
    tc_modern = TestClient(appmod.build_app(port=forced_old))
    state_modern = tc_modern.get("/api/state").json()
    paths_modern = tc_modern.get("/api/paths").json()

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
