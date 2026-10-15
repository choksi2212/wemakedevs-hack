"""Engine-hygiene + two-arm-AZ contracts (audit3/test-forensics).

Two REAL coverage gaps the mutation pass proved (mutations caught by zero
tests) are closed here, on the REAL engine:

- M5 (drop_graph turned into a no-op) was caught only INDIRECTLY, through
  engine-state leakage between tests — no test pinned the helper's own
  contract. Direct contract test below.
- M11 (the AZUser arm of the two-arm reachability deleted) was caught by
  ZERO tests: no estate anywhere puts an owned principal behind an Entra
  Global-Administrator JEWEL (the sample and every crafted estate reach only
  Group jewels). Pinned below, plus an xfail documenting the case-sensitivity
  divergence between the arm and crown_jewels() (mutation M11b: making the
  arm case-INSENSITIVE — i.e. correct — also changed nothing, because no
  test exercises a case-varied GA holder at all).

Every graph created here lives under the sever_audit3_tf* prefix and is
dropped by the test itself — engine hygiene is part of the contract under
test, not an accident of teardown.
"""
from __future__ import annotations

import pytest

from tests.conftest import drop_graph, requires_engine
from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import NormalizedGraph

pytestmark = [requires_engine]


def _fresh_port(name: str) -> FalkorGraphPort:
    port = FalkorGraphPort(graph_name=name)
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


@pytest.mark.xfail(
    strict=True,
    reason=(
        "known divergence (audit3/test-forensics, mutation M11b): arm 2 of "
        "REACHABILITY_ARM_TEMPLATES matches t.name case-SENSITIVELY while "
        "crown_jewels()/AZ_JEWELS_QUERY match toLower — a case-varied GA "
        "holder is a jewel and its paths enumerate, but reachability does "
        "not count it. Fix arm 2 to toLower(t.name) and remove this xfail."
    ),
)
def test_case_varied_ga_holder_is_counted_by_reachability():
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
        assert port.reachability() == 1  # ... but arm 2 misses the case-varied name
    finally:
        drop_graph(port, name)
