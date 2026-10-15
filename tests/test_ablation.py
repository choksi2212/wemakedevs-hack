"""Eval ablation — graph traversal vs keyword-only retrieval, on the REAL engine."""
from __future__ import annotations

import pytest

from tests.conftest import requires_engine, requires_sample, SAMPLE_DIR, drop_graph
from sever.eval.ablation import run_ablation

pytestmark = [requires_engine, requires_sample]


@pytest.fixture()
def port():
    from sever.core.falkor_port import FalkorGraphPort

    name = "sever_test_ablation"
    p = FalkorGraphPort(graph_name=name)
    drop_graph(p, name)
    from sever.etl.ad_collectors import parse_ad_dir

    p.load(parse_ad_dir(SAMPLE_DIR))
    yield p
    drop_graph(p, name)


def test_ablation_on_engine(port):
    result = run_ablation(port)
    score = result["score"]
    assert score["graph_answers_correct"] == "5/5"
    assert score["keyword_only_correct"] == "0/5"
    assert len(result["questions"]) == 5
    q1 = result["questions"][0]
    assert "Yes" in q1["graph"]["answer"]
    assert "undeterminable" in q1["keywords"]["answer"]
