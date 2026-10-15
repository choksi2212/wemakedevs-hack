"""ETL tests: edge-case hardening on synthetic collector dirs (DB-free AND
sample-free — they run anywhere) + parsing fidelity against the official
BloodHound CE sample.

The sample zip is downloaded once (outside the repo) from SpecterOps' docs:
https://bloodhound.specterops.io/get-started/quickstart/ce-ingest-sample-data
Point SEVER_SAMPLE_DIR at the extracted directory. Sample-fidelity tests are
gated per-test on its presence (@requires_sample); the synthetic edge-case
tests always run, so CI gets full ETL coverage without the download.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from tests.conftest import requires_sample
from sever.etl.ad_collectors import ABUSABLE_RELS, parse_ad_dir
from sever.etl.cypher_batches import build_batches, edge_batches, node_batches

SAMPLE_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample"
)


@pytest.fixture(scope="module")
def graph():
    return parse_ad_dir(SAMPLE_DIR)


@pytest.fixture(scope="module")
def stats(graph):
    return graph.stats


# ---- data fidelity on the sample (each test skips when the sample is absent) ----


@requires_sample
def test_parses_all_files(stats):
    assert stats["files"] == 31
    assert stats["node_count"] > 1400
    assert stats["edge_count"] > 12000


@requires_sample
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


@requires_sample
def test_domains_include_three_sample_domains(stats):
    # 3 collected domains + external trust-target unresolved domains
    assert stats["label_counts"].get("Domain", 0) >= 3


@requires_sample
def test_unresolved_principal_nodes_created_only_for_missing_refs(graph):
    unresolved = [n for n in graph.nodes.values() if n["props"].get("unresolved")]
    assert 5 <= len(unresolved) <= 20


@requires_sample
def test_membership_edges_present(stats):
    rc = stats["rel_counts"]
    assert rc.get("MEMBER_OF", 0) > 100


@requires_sample
def test_acl_edges_present(stats):
    rc = stats["rel_counts"]
    assert rc.get("OWNS", 0) > 0
    assert rc.get("WRITE_DACL", 0) > 0


@requires_sample
def test_trust_edges(stats):
    assert stats["rel_counts"].get("TRUSTED_BY", 0) >= 6


@requires_sample
def test_containment_edges(stats):
    assert stats["rel_counts"].get("CONTAINED_BY", 0) > 500


@requires_sample
def test_every_edge_endpoint_resolves(graph):
    ids = set(graph.nodes)
    dangling = [e for e in graph.edges.values() if e["src"] not in ids or e["dst"] not in ids]
    assert dangling == [], f"{len(dangling)} dangling edges, e.g. {dangling[:3]}"


@requires_sample
def test_abusable_rels_intersect_parsed_rels(stats):
    parsed = set(stats["rel_counts"])
    assert len(parsed & set(ABUSABLE_RELS)) >= 6


@requires_sample
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


# ---- Cypher batch emission ----


@requires_sample
def test_node_batches_cover_all_nodes(graph):
    total_rows = sum(len(b["params"]["rows"]) for b in node_batches(graph))
    assert total_rows == len(graph.nodes)


@requires_sample
def test_edge_batches_cover_all_edges(graph):
    total_rows = sum(len(b["params"]["rows"]) for b in edge_batches(graph))
    assert total_rows == len(graph.edges)


@requires_sample
def test_batch_query_shapes(graph):
    for b in build_batches(graph)[:4]:
        assert b["query"].startswith("UNWIND $rows AS")
        assert "MERGE" in b["query"]
        assert b["kind"] in ("node", "edge")


@requires_sample
def test_no_empty_batches(graph):
    assert all(len(b["params"]["rows"]) > 0 for b in build_batches(graph))


# ---- edge cases on synthetic collector dirs (fast, deterministic, DB-free) ----


def _collector_file(dirname, name, doc):
    """Write one SharpHound-style collector JSON into a scratch dir."""
    d = Path(dirname)
    d.mkdir(exist_ok=True)
    (d / name).write_text(json.dumps(doc), encoding="utf-8")


def test_empty_dir_is_a_hard_error(tmp_path):
    with pytest.raises(FileNotFoundError) as excinfo:
        parse_ad_dir(tmp_path)
    assert "no collector JSON files found" in str(excinfo.value)


def test_dir_without_json_files_is_a_hard_error(tmp_path):
    (tmp_path / "readme.txt").write_text("not a collector dump", encoding="utf-8")
    (tmp_path / "dump.csv").write_text("also not a collector", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        parse_ad_dir(tmp_path)


def test_malformed_json_fails_loud_not_silently(tmp_path):
    # fail-loud ETL: a truncated collector file aborts with a JSONDecodeError —
    # it is never silently skipped or half-ingested
    (tmp_path / "20240101000000_users.json").write_text(
        '{"data": [{"Obj', encoding="utf-8"
    )
    with pytest.raises(json.JSONDecodeError):
        parse_ad_dir(tmp_path)


def test_missing_or_empty_data_parses_to_zero_records(tmp_path):
    _collector_file(tmp_path, "20240101000000_users.json", {"meta": {"type": "users"}})  # no "data" key
    _collector_file(tmp_path, "20240101000000_groups.json", {"data": []})                # empty snapshot
    g = parse_ad_dir(tmp_path)
    assert g.stats["files"] == 2
    assert g.stats["node_count"] == 0
    assert g.stats["edge_count"] == 0
    assert g.stats["skipped"] == {}
    assert g.nodes == {} and g.edges == {}


def test_unknown_file_types_are_counted_not_parsed(tmp_path):
    _collector_file(
        tmp_path,
        "20240101000000_users.json",
        {"data": [{"ObjectIdentifier": "S-u1", "Properties": {"name": "u1"}}]},
    )
    _collector_file(tmp_path, "20240101000000_gibberish.json", {"data": [{"ObjectIdentifier": "S-x"}]})
    _collector_file(tmp_path, "20240102000000_gibberish.json", {"data": [{"ObjectIdentifier": "S-y"}]})
    _collector_file(tmp_path, "20240101000000_weird.json", {"data": [{"ObjectIdentifier": "S-z"}]})
    g = parse_ad_dir(tmp_path)
    # skip counters aggregate per unknown file type
    assert g.stats["skipped"] == {"unknown_type:gibberish": 2, "unknown_type:weird": 1}
    # unknown files' records never enter the graph
    assert "S-x" not in g.nodes and "S-y" not in g.nodes and "S-z" not in g.nodes
    assert g.stats["files"] == 4       # every *.json is seen; unknowns counted, not parsed
    assert g.stats["node_count"] == 1  # only the users record became a node


def test_file_type_detection_is_case_insensitive_and_tolerates_bare_stems(tmp_path):
    _collector_file(
        tmp_path,
        "20240101000000_USERS.json",
        {"data": [{"ObjectIdentifier": "S-u1", "Properties": {"name": "u1"}}]},
    )
    assert "S-u1" in parse_ad_dir(tmp_path).nodes  # uppercase type suffix still recognized
    (tmp_path / "20240101000000_USERS.json").unlink()
    _collector_file(
        tmp_path,
        "users.json",
        {"data": [{"ObjectIdentifier": "S-u2", "Properties": {"name": "u2"}}]},
    )
    assert "S-u2" in parse_ad_dir(tmp_path).nodes  # no "<ts>_" prefix: whole stem is the type
    (tmp_path / "users.json").unlink()
    _collector_file(tmp_path, "gibberish.json", {"data": []})
    g = parse_ad_dir(tmp_path)
    assert g.stats["skipped"] == {"unknown_type:gibberish": 1}  # bare unknown stem counted too


def test_records_missing_objectid_are_counted(tmp_path):
    _collector_file(
        tmp_path,
        "20240101000000_users.json",
        {"data": [
            {"Properties": {"name": "ghost"}},  # no ObjectIdentifier
            {"ObjectIdentifier": "S-u1", "Properties": {"name": "u1"}},
        ]},
    )
    g = parse_ad_dir(tmp_path)
    # one skip PER PASS — parsing is two-pass (nodes, then edges), and the
    # record is rejected in both
    assert g.stats["skipped"] == {"no_objectid": 2}
    assert set(g.nodes) == {"S-u1"}


def test_aces_missing_principal_or_right_are_counted(tmp_path):
    _collector_file(
        tmp_path,
        "20240101000000_users.json",
        {"data": [
            {"ObjectIdentifier": "S-u1", "Properties": {"name": "u1"}, "Aces": [
                {"RightName": "GenericAll"},                  # no PrincipalSID
                {"PrincipalSID": "S-p1"},                     # no RightName
                {"PrincipalSID": "", "RightName": "Enroll"},  # empty principal
            ]},
        ]},
    )
    g = parse_ad_dir(tmp_path)
    assert g.stats["skipped"] == {"ace_missing_fields": 3}
    assert g.stats["edge_count"] == 0


def test_right_to_rel_exotic_rights():
    from sever.etl.ad_collectors import _right_to_rel

    # exotic/extended ACE right names map mechanically onto rel types
    assert _right_to_rel("ExtendedRight") == "EXTENDED_RIGHT"
    assert _right_to_rel("Enroll") == "ENROLL"
    assert _right_to_rel("AutoEnroll") == "AUTO_ENROLL"
    assert _right_to_rel("AllExtendedRights") == "ALL_EXTENDED_RIGHTS"
    assert _right_to_rel("Self-Membership") == "SELF_MEMBERSHIP"      # hyphen -> underscore
    assert _right_to_rel("ReadGMSAPassword") == "READ_GMSAPASSWORD"   # acronym run stays intact
    # whitespace + camel-edge robustness
    assert _right_to_rel("  GenericAll ") == "GENERIC_ALL"
    assert _right_to_rel("WriteDacl") == "WRITE_DACL"
    assert _right_to_rel("GetChangesInFilteredSet") == "GET_CHANGES_IN_FILTERED_SET"
    assert _right_to_rel("DCSync") == "DCSYNC"  # single-word rights pass through untouched


def test_exotic_ace_rights_become_relationship_edges(tmp_path):
    _collector_file(
        tmp_path,
        "20240101000000_computers.json",
        {"data": [
            {"ObjectIdentifier": "S-comp", "Properties": {"name": "srv01"}, "Aces": [
                {"PrincipalSID": "S-p1", "PrincipalType": "User",
                 "RightName": "ExtendedRight", "IsInherited": True},
                {"PrincipalSID": "S-p2", "PrincipalType": "User", "RightName": "Enroll"},
                {"PrincipalSID": "S-p3", "PrincipalType": "User", "RightName": "Self-Membership"},
            ]},
        ]},
    )
    g = parse_ad_dir(tmp_path)
    rels = {e["rel"] for e in g.edges.values()}
    assert rels == {"EXTENDED_RIGHT", "ENROLL", "SELF_MEMBERSHIP"}
    # edges run principal -> resource (the ACE holder gets rights ON the object)
    er = next(e for e in g.edges.values() if e["rel"] == "EXTENDED_RIGHT")
    assert (er["src"], er["dst"]) == ("S-p1", "S-comp")
    assert er["props"] == {"inherited": True}    # IsInherited carried through
    en = next(e for e in g.edges.values() if e["rel"] == "ENROLL")
    assert en["props"] == {"inherited": False}   # absent flag defaults to False, not dropped
    # principals that were never collected materialize as unresolved nodes
    assert g.nodes["S-p1"]["props"]["unresolved"] is True
    assert g.nodes["S-p2"]["label"] == "User"
    assert g.stats["rel_counts"] == {"EXTENDED_RIGHT": 1, "ENROLL": 1, "SELF_MEMBERSHIP": 1}


def _edge_hash(g):
    """Stable digest over the edge SET (endpoints, rels, props)."""
    payload = sorted(
        (e["src"], e["dst"], e["rel"], json.dumps(e["props"], sort_keys=True, default=str))
        for e in g.edges.values()
    )
    return hashlib.sha256(json.dumps(payload).encode("utf-8")).hexdigest()


def test_parse_determinism_hash_on_edges(tmp_path):
    # a small but rel-rich estate: aces + membership + primary group
    _collector_file(
        tmp_path,
        "20240101000000_users.json",
        {"data": [
            {"ObjectIdentifier": "S-u1", "Properties": {"name": "u1"},
             "PrimaryGroupSID": "S-g1",
             "Aces": [
                 {"PrincipalSID": "S-p1", "RightName": "ExtendedRight"},
                 {"PrincipalSID": "S-p2", "RightName": "Enroll"},
             ]},
            {"ObjectIdentifier": "S-u2", "Properties": {"name": "u2"}},
        ]},
    )
    _collector_file(
        tmp_path,
        "20240101000000_groups.json",
        {"data": [
            {"ObjectIdentifier": "S-g1", "Properties": {"name": "g1"}, "Members": [
                {"ObjectIdentifier": "S-u2", "ObjectType": "User"},
            ]},
        ]},
    )
    g1, g2 = parse_ad_dir(tmp_path), parse_ad_dir(tmp_path)
    h1, h2 = _edge_hash(g1), _edge_hash(g2)
    assert h1 == h2                              # identical edge SET, not just edge count
    assert len(h1) == 64                          # sha256 hexdigest shape
    assert g1.edges.keys() == g2.edges.keys()    # identical ordering (sorted file walk)
    assert len(g1.edges) >= 4                    # the fixture actually exercises edges
