"""Eval ablation tests — the graph-vs-keywords receipt must hold on real data."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from sever.eval.ablation import run_ablation
from sever.etl.ad_collectors import parse_ad_dir

SAMPLE_DIR = os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample")
pytestmark = pytest.mark.skipif(
    not Path(SAMPLE_DIR).is_dir(), reason="sample data not present"
)


def test_ablation_on_sample():
    graph = parse_ad_dir(SAMPLE_DIR)
    result = run_ablation(graph)
    score = result["score"]
    assert score["graph_answers_correct"] == "5/5"
    assert score["keyword_only_correct"] == "0/5"
    assert len(result["questions"]) == 5
    # the hero beat facts are in the receipts
    q1 = result["questions"][0]
    assert "Yes" in q1["graph"]["answer"]
    assert "undeterminable" in q1["keywords"]["answer"]
