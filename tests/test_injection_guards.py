"""Cypher injection guards — pure-python, no engine required (audit/security).

Covers every string-interpolation seam into Cypher:
- _valid_rel: the live mutation gate in falkor_port.add_edge/cut
- _is_safe_rel: the batch-emission gate in cypher_batches.edge_batches
- node labels: closed vocabulary (TYPE_LABEL / _KNOWN_LABELS), asserted here
"""
from __future__ import annotations

import pytest

from sever.core.falkor_port import _valid_rel
from sever.core.jewels import TRAVERSAL_RELS
from sever.etl.ad_collectors import TYPE_LABEL, _KNOWN_LABELS, _right_to_rel, NormalizedGraph
from sever.etl.cypher_batches import _is_safe_rel, build_batches, edge_batches, node_batches

INJECTION_PAYLOADS = [
    "",
    "MEMBER_OF}]->(t) DETACH DELETE n //",
    "MEMBER_OF` RETURN 1 //",
    "MEMBER_OF:1",
    "MEMBER_OF x",
    "MEMBER_OF-RETURN-1",
    "X" * 65,
    "$(cat /etc/passwd)",
    "'; DROP GRAPH sever_demo; --",
    "MEMBER_OF\n",
]


def test_valid_rel_accepts_every_product_traversal_rel():
    for rel in TRAVERSAL_RELS:
        assert _valid_rel(rel), rel


def test_valid_rel_accepts_canonical_rel_types():
    for rel in ("MEMBER_OF", "GENERIC_ALL", "DCSYNC", "AZOwns", "AZVMAdminLogin"):
        assert _valid_rel(rel), rel


def test_valid_rel_rejects_injection_payloads():
    for payload in INJECTION_PAYLOADS:
        assert not _valid_rel(payload), payload
        assert not _is_safe_rel(payload), payload


def test_right_to_rel_output_stays_within_identifier_charset():
    # ACE RightName strings from collector data are data-file content; their
    # transform output must always land inside the safe charset.
    for right in (
        "GenericAll", "WriteDacl", "WriteOwner", "ForceChangePassword",
        "AllExtendedRights", "ReadGMSAPassword", "Self", "WriteProperty",
    ):
        assert _is_safe_rel(_right_to_rel(right)), right


def test_node_labels_are_a_closed_vocabulary():
    # node_batches interpolates labels into MERGE (n:{label} ...) — labels may
    # only ever come from the TYPE_LABEL enum, never from record content.
    assert set(TYPE_LABEL.values()) <= _KNOWN_LABELS
    assert all(_is_safe_rel(label) for label in TYPE_LABEL.values())


def test_edge_batches_reject_hostile_data_file_rel():
    g = NormalizedGraph()
    g.add_node("S-1-5-21-1-1", "User")
    g.add_node("S-1-5-21-1-2", "Group")
    g.add_edge("S-1-5-21-1-1", "S-1-5-21-1-2", "X}]->(t) DETACH DELETE n //")
    with pytest.raises(ValueError, match="unsafe relationship type"):
        edge_batches(g)


def test_build_batches_emits_only_param_bound_rows():
    g = NormalizedGraph()
    g.add_node("S-1-5-21-1-1", "User")
    g.add_node("S-1-5-21-1-2", "Group")
    g.add_edge("S-1-5-21-1-1", "S-1-5-21-1-2", "MEMBER_OF", {"primary": True})
    g.add_edge("S-1-5-21-1-1", "S-1-5-21-1-2", "AZOwns")
    batches = build_batches(g)
    assert batches
    for b in batches:
        # every value rides through $rows params — never through the query text
        assert "$rows" in b["query"]
        assert "S-1-5-21-1-1" not in b["query"]
