"""Live-engine regression: ETL parity, estate facts, cascade collapse.

The engine is the product's only substrate — there is no offline double.
"""
from __future__ import annotations

import os

import pytest

from tests.conftest import make_live_port, requires_engine, requires_sample, drop_graph, SAMPLE_DIR
from sever.agent.investigator import Investigator
from sever.etl.ad_collectors import parse_ad_dir
from sever.findings.stream import Finding

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"

pytestmark = [requires_engine, requires_sample]


def test_load_matches_etl_counts():
    from sever.core.falkor_port import FalkorGraphPort

    name = "sever_test_live_parity"
    port = FalkorGraphPort(graph_name=name)
    try:
        if port.node_count() == 0:
            port.load(parse_ad_dir(SAMPLE_DIR))
        normalized = parse_ad_dir(SAMPLE_DIR)
        assert port.node_count() == normalized.stats["node_count"]
        assert port.edge_count() == normalized.stats["edge_count"]
    finally:
        drop_graph(port, name)


def test_estate_facts_and_cascade():
    port = make_live_port("sever_test_live_cascade")
    try:
        inv = Investigator(port)
        report = inv.triage(Finding("F-L1", "credential_breach", HERO))
        assert report.after["reachability"] == 1
        assert report.proposal, "agent must propose cuts against the live engine"
        rounds = 0
        while port.reachability() > 0 and rounds < 4:
            prop = inv.propose(limit=3)
            if not prop:
                break
            top = prop[0]
            receipt = inv.approve_and_cut(top["src"], top["dst"], top["rel"])
            assert receipt["cut"]["relationships_removed"] >= 1
            assert receipt["requery_ms"] is not None
            rounds += 1
        assert port.reachability() == 0, f"cascade must collapse within {rounds} gated cuts"
    finally:
        drop_graph(port, "sever_test_live_cascade")
