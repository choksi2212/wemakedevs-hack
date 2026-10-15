"""ETL tests against the official BloodHound CE sample data.

The sample zip is downloaded once (outside the repo) from SpecterOps' docs:
https://bloodhound.specterops.io/get-started/quickstart/ce-ingest-sample-data
Point SEVER_SAMPLE_DIR at the extracted directory. Tests skip if it is absent
(e.g. CI) — they are data-fidelity tests, not unit tests.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sever.etl.ad_collectors import ABUSABLE_RELS, parse_ad_dir
from sever.etl.cypher_batches import build_batches, edge_batches, node_batches

SAMPLE_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR",
    str(Path(__file__).resolve().parents[1] / "data" / "ad_sample"),
)

pytestmark = pytest.mark.skipif(
    not Path(SAMPLE_DIR).is_dir(), reason=f"sample data not present at {SAMPLE_DIR}"
)


@pytest.fixture(scope="module")
def graph():
    return parse_ad_dir(SAMPLE_DIR)


@pytest.fixture(scope="module")
def stats(graph):
    return graph.stats


def test_parses_all_files(stats):
    assert stats["files"] == 31
    assert stats["node_count"] > 1400
    assert stats["edge_count"] > 12000


def test_label_counts(stats):
    # counts are UNIQUE objectids (config-partition GUIDs and SIDs repeat across
    # the 3 domain snapshots: raw records 1718 -> 1471 unique + 9 unresolved principals)
    lc = stats["label_counts"]
    assert lc.get("User") == 99        # 100 raw records, one SID listed twice
    assert lc.get("Group") == 219      # 285 raw, 66 cross-snapshot dupes
    assert lc.get("Computer") == 34
    assert lc.get("Container") == 948  # 1121 raw, cross-snapshot dupes
    assert lc.get("CertTemplate") == 106
    assert lc.get("OU") == 20
    assert lc.get("GPO") == 32
    assert lc.get("EnterpriseCA") == 4


def test_domains_include_three_sample_domains(stats):
    # 3 collected domains + external trust-target unresolved domains
    assert stats["label_counts"].get("Domain", 0) >= 3


def test_unresolved_principal_nodes_created_only_for_missing_refs(graph):
    unresolved = [n for n in graph.nodes.values() if n["props"].get("unresolved")]
    assert 5 <= len(unresolved) <= 20


def test_membership_edges_present(stats):
    rc = stats["rel_counts"]
    assert rc.get("MEMBER_OF", 0) > 100


def test_acl_edges_present(stats):
    rc = stats["rel_counts"]
    assert rc.get("OWNS", 0) > 0
    assert rc.get("WRITE_DACL", 0) > 0


def test_trust_edges(stats):
    assert stats["rel_counts"].get("TRUSTED_BY", 0) >= 6


def test_containment_edges(stats):
    assert stats["rel_counts"].get("CONTAINED_BY", 0) > 500


def test_every_edge_endpoint_resolves(graph):
    ids = set(graph.nodes)
    dangling = [e for e in graph.edges.values() if e["src"] not in ids or e["dst"] not in ids]
    assert dangling == [], f"{len(dangling)} dangling edges, e.g. {dangling[:3]}"


def test_abusable_rels_intersect_parsed_rels(stats):
    parsed = set(stats["rel_counts"])
    assert len(parsed & set(ABUSABLE_RELS)) >= 6


def test_parse_is_deterministic():
    g1 = parse_ad_dir(SAMPLE_DIR)
    g2 = parse_ad_dir(SAMPLE_DIR)
    s1 = json.dumps(
        [g1.nodes[k] for k in sorted(g1.nodes)], sort_keys=True, default=str
    )
    s2 = json.dumps(
        [g2.nodes[k] for k in sorted(g2.nodes)], sort_keys=True, default=str
    )
    assert s1 == s2


def test_parse_is_deterministic_edge_set_hash():
    """Two parses of the same directory must yield an identical EDGE set —
    hashed, not just node-compared: the edge dict is the attack-path substrate."""
    import hashlib

    def edge_hash(g):
        payload = sorted(
            (e["src"], e["dst"], e["rel"], json.dumps(e["props"], sort_keys=True, default=str))
            for e in g.edges.values()
        )
        return hashlib.sha256(json.dumps(payload).encode()).hexdigest()

    g1 = parse_ad_dir(SAMPLE_DIR)
    g2 = parse_ad_dir(SAMPLE_DIR)
    assert edge_hash(g1) == edge_hash(g2)
    assert len(g1.edges) == len(g2.edges) > 0


# ---- derivation fidelity (audit: verified against concrete sample records) ----


def test_local_admin_edges_derived_from_localgroups_results(graph):
    """SharpHound CE v6 puts local-group members under "Results"; only the
    local ADMINISTRATORS group (RID -544) yields ADMIN_TO (BloodHound CE
    semantics — sample also lists Users/Guests/RemoteDesktopUsers)."""
    admin_to = [e for e in graph.edges.values() if e["rel"] == "ADMIN_TO"]
    assert len(admin_to) >= 10
    # concrete: BUILTIN Administrator (RID -500) is local admin of DC01
    dc01 = "S-1-5-21-2697957641-2271029196-387917394-1000"
    assert any(
        e["src"].endswith("-500") and e["dst"] == dc01 for e in admin_to
    )
    # concrete: WRAITH Domain Admins (-512) admin their DC
    assert any(
        e["src"].endswith("-512") and e["dst"].endswith("-1000") for e in admin_to
    )
    # concrete: members of the local Users group (RID -545) are NOT admins
    assert not any(e["props"].get("local_group_id", "").endswith("-545") for e in admin_to)


def test_delegation_edge_points_privilege_holder_to_target(graph):
    """msDS-AllowedToDelegateTo lives on the DELEGATOR; sample record KRB-DEL-01
    delegates to DC01 — the edge must run KRB-DEL-01 -> DC01."""
    edges = [e for e in graph.edges.values() if e["rel"] == "ALLOWED_TO_DELEGATE"]
    assert edges, "no ALLOWED_TO_DELEGATE edges derived"
    krb_del = "S-1-5-21-2697957641-2271029196-387917394-2171"
    dc01 = "S-1-5-21-2697957641-2271029196-387917394-1000"
    assert all((e["src"], e["dst"]) == (krb_del, dc01) for e in edges)


def test_rbcd_edge_points_actor_to_target(graph):
    """msDS-AllowedToActOnBehalfOfOtherIdentity lives on the TARGET computer:
    the sample's EXTCA01 record lists EXTCA02 -> edge EXTCA02 -> EXTCA01."""
    edges = [e for e in graph.edges.values() if e["rel"] == "ALLOWED_TO_ACT"]
    assert edges, "no ALLOWED_TO_ACT edges derived"
    extca02 = "S-1-5-21-3702535222-3822678775-2090119576-1169"
    extca01 = "S-1-5-21-3702535222-3822678775-2090119576-1120"
    assert all((e["src"], e["dst"]) == (extca02, extca01) for e in edges)


def test_abusable_rels_cover_every_emitted_traversable_rel(graph):
    """Every rel the ETL emits that the engine can chain must be in the
    documented enum (audit finding: ADD_MEMBER, READ_GMSAPASSWORD etc. were
    missing while phantom ESC1/ESC2/AUTO_ENROLL were listed)."""
    from sever.core.jewels import TRAVERSAL_RELS_SET

    emitted = set(graph.stats["rel_counts"])
    assert emitted & TRAVERSAL_RELS_SET <= ABUSABLE_RELS


# ---- Cypher batch emission ----


def test_node_batches_cover_all_nodes(graph):
    total_rows = sum(len(b["params"]["rows"]) for b in node_batches(graph))
    assert total_rows == len(graph.nodes)


def test_edge_batches_cover_all_edges(graph):
    total_rows = sum(len(b["params"]["rows"]) for b in edge_batches(graph))
    assert total_rows == len(graph.edges)


def test_batch_query_shapes(graph):
    for b in build_batches(graph)[:4]:
        assert b["query"].startswith("UNWIND $rows AS")
        assert "MERGE" in b["query"]
        assert b["kind"] in ("node", "edge")


def test_no_empty_batches(graph):
    assert all(len(b["params"]["rows"]) > 0 for b in build_batches(graph))
