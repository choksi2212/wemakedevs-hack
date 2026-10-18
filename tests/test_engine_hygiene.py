"""Engine-hygiene + two-arm-AZ contracts (audit3/test-forensics).

Two REAL coverage gaps the mutation pass proved (mutations caught by zero
tests) are closed here, on the REAL engine:

- M5 (drop_graph turned into a no-op) was caught only INDIRECTLY, through
  engine-state leakage between tests — no test pinned the helper's own
  contract. Direct contract test below.
- M11 (the AZUser arm of the two-arm reachability deleted) was caught by
  ZERO tests: no estate anywhere puts an owned principal behind an Entra
  Global-Administrator JEWEL (the sample and every crafted estate reach only
  Group jewels). Pinned below as a positive test, including the case-varied
  GA holder — the historical M11b case-sensitivity divergence between the
  arm and crown_jewels() is FIXED (the arm mirrors AZ_JEWELS_QUERY's
  toLower), so the old xfail is gone and no xfail remains in this file.

Every graph created here lives under the sever_audit3_tf* prefix and is
dropped by the test itself — engine hygiene is part of the contract under
test, not an accident of teardown. The keyspace sweep at the end ASSERTS
it: no key under any test prefix survives the suite.
"""
from __future__ import annotations

import os

import pytest

from tests.conftest import drop_graph, prefixed, requires_engine
from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import NormalizedGraph

pytestmark = [requires_engine]


def _fresh_port(name: str) -> FalkorGraphPort:
    # host/port from env exactly like conftest.make_live_port (audit M75):
    # the gating probe honors SEVER_FALKOR_HOST/PORT, so these tests must
    # connect to the same endpoint instead of silently defaulting to
    # 127.0.0.1:6379 — otherwise the gate and the tests disagree on which
    # engine is under test.
    name = prefixed(name)
    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=name,
    )
    drop_graph(port, name)
    return port


def test_drop_graph_contract_is_direct_and_idempotent():
    """drop_graph's own contract, pinned directly (mutation M5): the key is
    really deleted, a second delete never raises, and a missing key is safe."""
    name = "sever_audit3_tf_drop"
    port = _fresh_port(name)
    try:
        g = NormalizedGraph()
        g.add_node("S-drop-1", "User", {"name": "u"})
        port.load(g)
        assert port.node_count() == 1
        drop_graph(port, name)
        assert port.node_count() == 0, "GRAPH.DELETE must actually delete the key"
        drop_graph(port, name)  # idempotent: re-deleting an absent key never raises
        drop_graph(port, "sever_audit3_tf_missing")  # never-existed keys are safe too
        assert port.node_count() == 0
    finally:
        drop_graph(port, name)


def test_cloud_jewel_is_reachable_via_the_az_arm():
    """The two-arm reachability's SECOND arm (mutation M11 deleted it and zero
    tests failed): an owned cloud principal that reaches an AZUser Global-
    Administrator holder — a crown jewel with NO AD Group jewel in the
    estate — must count, and cutting the bridge must collapse it."""
    name = "sever_audit3_tf_azarm"
    port = _fresh_port(name)
    try:
        g = NormalizedGraph()
        g.add_node("az-ga", "AZUser", {"name": "ops-GlobalAdministrator"})
        g.add_node("az-pwned", "AZUser", {"name": "cloud-compromised"})
        g.add_edge("az-pwned", "az-ga", "AZMemberOf")
        port.load(g)
        assert port.crown_jewels() == ["az-ga"]
        port.mark_owned("az-pwned")
        assert port.paths_to_jewels("az-pwned"), "path to the cloud jewel enumerated"
        assert port.reachability() == 1, "the AZUser arm must count cloud-jewel breaches"
        assert port.cut("az-pwned", "az-ga", "AZMemberOf") == 1
        assert port.reachability() == 0, "severing the bridge collapses the breach"
    finally:
        drop_graph(port, name)


def test_case_varied_ga_holder_is_counted_by_reachability():
    """Divergence FIXED (audit3/interdiction-logic): arm 2 now mirrors
    AZ_JEWELS_QUERY with toLower, so case-varied GA holders are counted by
    reachability exactly like crown_jewels() counts them as jewels. The
    xfail pin from test-forensics (M11b) flipped to a positive assertion."""
    name = "sever_audit3_tf_azcase"
    port = _fresh_port(name)
    try:
        g = NormalizedGraph()
        g.add_node("az-ga", "AZUser", {"name": "ops-globaladministrator"})  # case-varied
        g.add_node("az-pwned", "AZUser", {"name": "cloud-compromised"})
        g.add_edge("az-pwned", "az-ga", "AZMemberOf")
        port.load(g)
        assert port.crown_jewels() == ["az-ga"]  # jewel by the toLower match
        port.mark_owned("az-pwned")
        assert port.paths_to_jewels("az-pwned")  # paths DO enumerate ...
        assert port.reachability() == 1  # arm 2 counts the case-varied GA jewel (toLower)
    finally:
        drop_graph(port, name)


# every engine key the test suites create, by prefix — the keyspace sweep
# (audit L90) asserts none of these survive the suite on a shared engine.
# Product/script keys (sever_demo, sever_tenantNNN, telemetry{...}) are
# deliberately NOT listed: the sweep polices test hygiene only.
TEST_KEY_PREFIXES = (
    "sever_test_",           # conftest.make_live_port + module-local ports
    "sever_audit3_tf",       # this module
    "sever_audit3_il",       # interdiction invariants
    "sever_audit3_cl",       # console e2e / console resilience
    "sever_audit7_",         # perf equivalence + console perf folds
    "sever_audit8_",         # boot outage containment
    "sever_conftest_probe",  # the conftest reachability probe (M71)
)


def test_keyspace_sweep_no_test_key_survives_the_suite():
    """L90: hygiene is ASSERTED, not just practiced. Defined last, so every
    earlier test in this module has already dropped its graph in finally:
    scan the WHOLE keyspace and assert no key under any test prefix
    remains — a missing teardown, a crashed-run leftover, or a re-leaked
    conftest probe key (M71) fails here instead of poisoning the next
    session against one shared engine."""
    port = _fresh_port("sever_audit3_tf_sweep")  # drops any crashed-run leftover
    try:
        seen: list[str] = []
        cursor = 0
        while True:
            cursor, page = port.graph.client.execute_command("SCAN", cursor)
            seen.extend(
                (k.decode() if isinstance(k, bytes) else str(k)) for k in (page or [])
            )
            cursor = int(cursor)
            if cursor == 0:
                break
        leaked = sorted(k for k in seen if k.startswith(TEST_KEY_PREFIXES))
        assert leaked == [], (
            f"test-prefixed keys survived on the engine: {leaked} — every "
            "suite must drop the keys it creates (clean one-time leftovers "
            "from crashed runs, then this pin holds)"
        )
    finally:
        drop_graph(port, "sever_audit3_tf_sweep")
