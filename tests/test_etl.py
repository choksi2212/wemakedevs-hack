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
    "SEVER_SAMPLE_DIR",
    str(Path(__file__).resolve().parents[1] / "data" / "ad_sample"),
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
    # exact pins: the docs (README §12, JUDGE_QA) attribute the estate's
    # 1,480 nodes / 12,450 edges to THIS file — loose bounds would let the
    # estate drift silently (audit M76/X10; values live-verified against the
    # official SpecterOps sample and also engine-pinned in tests/test_ports.py)
    assert stats["files"] == 31
    assert stats["node_count"] == 1480
    assert stats["edge_count"] == 12450


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
def test_unresolved_principal_count_in_expected_band(graph):
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
def test_parse_is_deterministic_nodes():
    g1 = parse_ad_dir(SAMPLE_DIR)
    g2 = parse_ad_dir(SAMPLE_DIR)
    s1 = json.dumps(
        [g1.nodes[k] for k in sorted(g1.nodes)], sort_keys=True, default=str
    )
    s2 = json.dumps(
        [g2.nodes[k] for k in sorted(g2.nodes)], sort_keys=True, default=str
    )
    assert s1 == s2


@requires_sample
def test_parse_is_deterministic_edge_set_hash():
    """Two parses of the same directory must yield an identical EDGE set —
    hashed, not just node-compared: the edge dict is the attack-path substrate."""
    g1 = parse_ad_dir(SAMPLE_DIR)
    g2 = parse_ad_dir(SAMPLE_DIR)
    assert _edge_hash(g1) == _edge_hash(g2)
    assert len(g1.edges) == len(g2.edges) > 0


# ---- derivation fidelity (audit: verified against concrete sample records) ----


@requires_sample
def test_local_admin_edges_derived_from_localgroups_results(graph):
    """SharpHound CE v6 puts local-group members under "Results"; only the
    local ADMINISTRATORS group (RID -544) yields ADMIN_TO (BloodHound CE
    semantics — sample also lists Users/Guests/RemoteDesktopUsers)."""
    admin_to = [e for e in graph.edges.values() if e["rel"] == "ADMIN_TO"]
    assert len(admin_to) >= 10
    # concrete: the domain Administrator (RID -500) is local admin of DC01
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


@requires_sample
def test_delegation_edge_points_privilege_holder_to_target(graph):
    """msDS-AllowedToDelegateTo lives on the DELEGATOR; sample record KRB-DEL-01
    delegates to DC01 — the edge must run KRB-DEL-01 -> DC01."""
    edges = [e for e in graph.edges.values() if e["rel"] == "ALLOWED_TO_DELEGATE"]
    assert edges, "no ALLOWED_TO_DELEGATE edges derived"
    krb_del = "S-1-5-21-2697957641-2271029196-387917394-2171"
    dc01 = "S-1-5-21-2697957641-2271029196-387917394-1000"
    assert all((e["src"], e["dst"]) == (krb_del, dc01) for e in edges)


@requires_sample
def test_rbcd_edge_points_actor_to_target(graph):
    """msDS-AllowedToActOnBehalfOfOtherIdentity lives on the TARGET computer:
    the sample's EXTCA01 record lists EXTCA02 -> edge EXTCA02 -> EXTCA01."""
    edges = [e for e in graph.edges.values() if e["rel"] == "ALLOWED_TO_ACT"]
    assert edges, "no ALLOWED_TO_ACT edges derived"
    extca02 = "S-1-5-21-3702535222-3822678775-2090119576-1169"
    extca01 = "S-1-5-21-3702535222-3822678775-2090119576-1120"
    assert all((e["src"], e["dst"]) == (extca02, extca01) for e in edges)


@requires_sample
def test_abusable_rels_cover_every_emitted_traversable_rel(graph):
    """Every rel the ETL emits that the engine can chain must be in the
    documented enum (audit finding: ADD_MEMBER, READ_GMSAPASSWORD etc. were
    missing while phantom ESC1/ESC2/AUTO_ENROLL were listed)."""
    from sever.core.jewels import TRAVERSAL_RELS_SET

    emitted = set(graph.stats["rel_counts"])
    assert emitted & TRAVERSAL_RELS_SET <= ABUSABLE_RELS
    # owner resolution #3: the sample's cert-template PKI flag writes
    # (WRITE_PKIENROLLMENT_FLAG / WRITE_PKINAME_FLAG, 2+2 edges) now chain —
    # they must be in BOTH enums
    assert {"WRITE_PKIENROLLMENT_FLAG", "WRITE_PKINAME_FLAG"} <= (
        TRAVERSAL_RELS_SET & ABUSABLE_RELS
    )
    assert "WRITE_PKIENROLLMENT_FLAG" in emitted and "WRITE_PKINAME_FLAG" in emitted


def test_traversal_and_abusable_enums_are_two_way_aligned():
    """Owner resolution #3 (audit M64/X14/L94): the traversal set and the
    ETL's documented abusable enum are aligned BOTH ways, DB-free and
    sample-free —

    - every AD-side rel the engine can chain is listed in ABUSABLE_RELS
      (the one-directional sample test above cannot catch omissions the
      sample happens not to emit, e.g. EXTENDED_RIGHT/GENERIC_RIGHT);
    - every abusable rel is attacker-chainable in TRAVERSAL_RELS except
      the one documented exception (ENROLL — BloodHound CE marks the
      Enroll edge non-traversable too);
    - the traversal set counts 45 (43 + the two PKI flag rights) — the
      number README §1 / GRAPH_MODEL / CYPHER.md publish.
    """
    from sever.core.jewels import TRAVERSAL_RELS, TRAVERSAL_RELS_SET

    assert len(TRAVERSAL_RELS) == 45
    hybrid = {r for r in TRAVERSAL_RELS if r.startswith("AZ")} | {"SYNCED_TO"}
    ad_traversal = TRAVERSAL_RELS_SET - hybrid
    # traversable (AD-side) => abusable/documented
    assert ad_traversal <= ABUSABLE_RELS, sorted(ad_traversal - ABUSABLE_RELS)
    # abusable => chainable, minus the documented non-traversable exception
    non_traversable = ABUSABLE_RELS - TRAVERSAL_RELS_SET
    assert non_traversable == {"ENROLL"}, sorted(non_traversable)
    # the four audit-flagged rels are in both enums
    assert {"WRITE_PKIENROLLMENT_FLAG", "WRITE_PKINAME_FLAG",
            "EXTENDED_RIGHT", "GENERIC_RIGHT"} <= ABUSABLE_RELS
    assert {"WRITE_PKIENROLLMENT_FLAG", "WRITE_PKINAME_FLAG"} <= TRAVERSAL_RELS_SET


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


def test_mixed_prop_rel_group_preserves_props_regardless_of_row_order(tmp_path):
    """audit M65: the per-rel query shape used to be chosen from rows[0]
    alone, so a mixed rel group whose FIRST row has empty props silently
    dropped every later row's props at Cypher load. MEMBER_OF is inherently
    mixed; the groups file sorts before users, so the prop-less
    Members-derived edge is row 0 here — the exact shape the official
    sample escapes only by luck (a computer's primary-group edge sorts
    first there).
    """
    _collector_file(
        tmp_path, "20240101000000_groups.json",
        {"data": [
            {"ObjectIdentifier": "S-g1", "Properties": {"name": "g1"}, "Members": [
                {"ObjectIdentifier": "S-u2", "ObjectType": "User"},
            ]},
        ]},
    )
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [
            {"ObjectIdentifier": "S-u2", "Properties": {"name": "u2"},
             "PrimaryGroupSID": "S-g1"},
        ]},
    )
    g = parse_ad_dir(tmp_path)
    mo = [e for e in g.edges.values() if e["rel"] == "MEMBER_OF"]
    assert len(mo) == 2  # the prop-less member edge AND the primary edge
    batches = [b for b in edge_batches(g) if b["kind"] == "edge"
               and "MEMBER_OF" in b["query"]]
    assert len(batches) == 2  # split: one has-props sub-batch, one no-props
    # the prop-carrying row rides the props_key MERGE with its props intact
    props_batch = next(b for b in batches if "props_key" in b["query"])
    assert len(props_batch["params"]["rows"]) == 1
    row = props_batch["params"]["rows"][0]
    assert row["props"] == {"primary": True}
    assert row["props_key"] == '{"primary": true}'
    # the prop-less row keeps the plain MERGE — no props_key invented for it
    plain_batch = next(b for b in batches if "props_key" not in b["query"])
    assert len(plain_batch["params"]["rows"]) == 1
    assert "props_key" not in plain_batch["params"]["rows"][0]
    # every emitted batch is homogeneous (all rows carry props_key or none do)
    # and the split still covers every edge exactly once
    for b in edge_batches(g):
        if b["kind"] != "edge":
            continue
        rows = b["params"]["rows"]
        assert all("props_key" in r for r in rows) or all(
            "props_key" not in r for r in rows), b["query"]
    assert sum(len(b["params"]["rows"]) for b in batches) == len(g.edges)


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


def test_meta_type_mismatch_is_counted_filename_stays_authoritative(tmp_path):
    """audit L66: the document's meta.type was never read or cross-checked
    against the filename-derived collector type. A divergence between the
    two is now visible under ``type_mismatch:{file}`` — and the FILENAME
    stays authoritative, so typing never changes."""
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"meta": {"type": "computers", "version": 6},
         "data": [{"ObjectIdentifier": "S-u1", "Properties": {"name": "u1"}}]},
    )
    _collector_file(
        tmp_path, "20240101000000_groups.json",
        {"meta": {"type": "groups", "version": 6},
         "data": [{"ObjectIdentifier": "S-g1", "Properties": {"name": "g1"}}]},
    )
    g = parse_ad_dir(tmp_path)
    # the users file's meta claims computers -> exactly one visible mismatch
    assert g.stats["skipped"] == {"type_mismatch:20240101000000_users.json": 1}
    # typing stays filename-derived: the record is still a User
    assert g.nodes["S-u1"]["label"] == "User"
    assert g.nodes["S-g1"]["label"] == "Group"
    # an unknown meta type (not in TYPE_LABEL) is NOT a mismatch: the
    # filename remains the only typing authority for unrecognized meta
    _collector_file(
        tmp_path, "20240101000000_computers.json",
        {"meta": {"type": "gibberish-meta", "version": 6}, "data": []},
    )
    g = parse_ad_dir(tmp_path)
    assert g.stats["skipped"] == {"type_mismatch:20240101000000_users.json": 1}


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


# ============================================================================
# audit3/etl-logic — deep-audit tests
#
# (a) raw<->emitted derivation proofs against the real CE sample (each branch
#     cross-checked with THREE concrete record ObjectIdentifiers),
# (b) 3x re-parse determinism including per-label counts,
# (c) adversarial/hostile collector inputs (DB-free, always run): the parser
#     must parse cleanly or fail LOUD — never emit a garbage edge, never crash
#     silently. Every hostile parse also asserts the unresolved-principal
#     invariant: every edge endpoint exists as a node.
# ============================================================================


def _assert_invariants(g, *, allow_empty=True):
    """Unresolved-principal invariant (DB-free): every edge endpoint is a node,
    and every node prop value is a FalkorDB-safe primitive."""
    ids = set(g.nodes)
    dangling = [e for e in g.edges.values() if e["src"] not in ids or e["dst"] not in ids]
    assert dangling == [], f"{len(dangling)} dangling edges, e.g. {dangling[:3]}"
    for n in g.nodes.values():
        for k, v in n["props"].items():
            assert not isinstance(v, (dict, list)), f"non-primitive node prop {k} on {n['objectid']}"
    for e in g.edges.values():
        for k, v in e["props"].items():
            assert not isinstance(v, (dict, list)), f"non-primitive edge prop {k} on {e}"


# ---- (b) determinism: 3x re-parse, byte-identical edges AND per-label counts ----


@requires_sample
def test_parse_determinism_3x_edge_hash_and_per_label_counts():
    """Three parses of the real sample: byte-identical edge-set hashes AND
    identical per-label node counts / per-rel edge counts (extends the 2x
    edge-hash determinism test)."""
    graphs = [parse_ad_dir(SAMPLE_DIR) for _ in range(3)]
    for g in graphs:
        _assert_invariants(g)
    assert len({len(g.edges) for g in graphs}) == 1
    assert len({_edge_hash(g) for g in graphs}) == 1, "edge sets differ across parses"
    assert len({json.dumps(g.stats["label_counts"], sort_keys=True) for g in graphs}) == 1
    assert len({json.dumps(g.stats["rel_counts"], sort_keys=True) for g in graphs}) == 1
    # stats agree with the graph itself (label/rel censuses are not lies)
    for g in graphs:
        assert g.stats["node_count"] == len(g.nodes)
        assert g.stats["edge_count"] == len(g.edges)
        assert sum(g.stats["label_counts"].values()) == len(g.nodes)
        assert sum(g.stats["rel_counts"].values()) == len(g.edges)


# ---- (a) derivation proofs: raw sample records <-> emitted edges ----


def _raw_records(sample_dir, *ftypes):
    """(oid, record) for every record of the given collector file types
    (no filter -> every type)."""
    out = []
    for f in sorted(Path(sample_dir).glob("*.json")):
        stem = f.stem
        ftype = stem.split("_", 1)[1].lower() if "_" in stem else stem.lower()
        if ftypes and ftype not in ftypes:
            continue
        doc = json.loads(f.read_text(encoding="utf-8"))
        for rec in doc.get("data", []):
            out.append((str(rec.get("ObjectIdentifier") or ""), rec))
    return out


@requires_sample
def test_trust_edges_match_raw_trust_records(graph):
    """Every raw Trusts entry emits exactly one TRUSTED_BY edge
    record-domain -> TargetDomainSid with direction/trusttype preserved;
    uncollected targets materialize as external Domain nodes.

    Concrete sample records (objectids):
      - S-1-5-21-2697957641-2271029196-387917394 (PHANTOM.CORP) trusts
        S-1-5-21-1852147331-818484528-1557274963 (REVENANT.CORP),
        direction "Inbound", type External;
      - S-1-5-21-2697957641-2271029196-387917394 (PHANTOM.CORP) trusts
        S-1-5-21-2845847946-3451170323-4261139666 (GHOST.CORP, collected);
      - S-1-5-21-3702535222-3822678775-2090119576 (WRAITH.CORP) trusts
        S-1-5-21-720005541-26010935-3948964793 (CHILD.WRAITH.CORP).
    """
    raw = {
        (oid, str(t.get("TargetDomainSid")), t.get("TrustDirection"), t.get("TrustType"))
        for oid, rec in _raw_records(SAMPLE_DIR, "domains")
        for t in (rec.get("Trusts") or []) if isinstance(t, dict)
    }
    emitted = {
        (e["src"], e["dst"], e["props"].get("direction"), e["props"].get("trusttype"))
        for e in graph.edges.values() if e["rel"] == "TRUSTED_BY"
    }
    assert raw == emitted and len(raw) == 6
    phantom = "S-1-5-21-2697957641-2271029196-387917394"
    wraith = "S-1-5-21-3702535222-3822678775-2090119576"
    revenant = "S-1-5-21-1852147331-818484528-1557274963"
    child = "S-1-5-21-720005541-26010935-3948964793"
    # uncollected trust targets are flagged external Domain nodes
    assert graph.nodes[revenant]["label"] == "Domain"
    assert graph.nodes[revenant]["props"].get("external") is True
    assert graph.nodes[revenant]["props"].get("name") == "REVENANT.CORP"
    assert graph.nodes[child]["props"].get("external") is True
    assert graph.nodes[child]["props"].get("name") == "CHILD.WRAITH.CORP"
    # collected trust targets keep their own record's node (no external flag)
    ghost = "S-1-5-21-2845847946-3451170323-4261139666"
    assert graph.nodes[ghost]["label"] == "Domain"
    assert not graph.nodes[ghost]["props"].get("external")
    assert (phantom, revenant, "Inbound", "External") in emitted
    assert (wraith, child, "Bidirectional", "ParentChild") in emitted


@requires_sample
def test_admin_to_matches_raw_localgroups_544_pairs(graph):
    """ADMIN_TO is derived from exactly the raw local-group RID -544 Results,
    nothing more, nothing less. Concrete sample records (objectids):
      - S-1-5-21-2697957641-2271029196-387917394-500 (ADMINISTRATOR) admin of
        ...-1000 (DC01) via local group PHANTOM.CORP-S-1-5-32-544;
      - ...-1138 (Tier2Support) admin of ...-1120 (PAYMENT01);
      - ...-2113 (JD, PHANTOM user) admin of WRAITH's ...-1000 (EXTDC01) —
        the cross-domain local-admin edge survives.
    """
    raw_pairs, non_admin_pairs = set(), set()
    for oid, rec in _raw_records(SAMPLE_DIR, "computers"):
        for lg in rec.get("LocalGroups") or []:
            lg_oid = str(lg.get("ObjectIdentifier") or "")
            members = lg.get("Results") or lg.get("Members") or []
            for m in members:
                if not isinstance(m, dict):
                    continue
                sid = str(m.get("ObjectIdentifier") or "")
                if not sid:
                    continue
                if lg_oid.rsplit("-", 1)[-1] == "544":
                    raw_pairs.add((sid, oid))
                else:
                    non_admin_pairs.add((sid, oid))
    emitted = {(e["src"], e["dst"]) for e in graph.edges.values() if e["rel"] == "ADMIN_TO"}
    assert raw_pairs == emitted and len(emitted) == 13
    assert non_admin_pairs & emitted == set(), "non-admin local-group member got ADMIN_TO"
    assert ("S-1-5-21-2697957641-2271029196-387917394-500",
            "S-1-5-21-2697957641-2271029196-387917394-1000") in emitted
    assert ("S-1-5-21-2697957641-2271029196-387917394-1138",
            "S-1-5-21-2697957641-2271029196-387917394-1120") in emitted
    assert ("S-1-5-21-2697957641-2271029196-387917394-2113",
            "S-1-5-21-3702535222-3822678775-2090119576-1000") in emitted
    # the local-group id rides along as a prop (audit trail for the derivation)
    e = next(e for e in graph.edges.values() if e["rel"] == "ADMIN_TO"
             and e["src"].endswith("-500") and e["dst"].endswith("-1000"))
    assert e["props"]["local_group_id"] == "PHANTOM.CORP-S-1-5-32-544"


@requires_sample
def test_delegation_and_rbcd_edges_match_raw_refs(graph):
    """Raw AllowedToDelegate refs (on the delegator) -> ALLOWED_TO_DELEGATE
    delegator->target; raw AllowedToAct refs (on the target) ->
    ALLOWED_TO_ACT actor->target. Concrete: KRB-DEL-01 (...-2171) delegates to
    DC01 (...-1000); EXTCA01 (...-1120) lists EXTCA02 (...-1169)."""
    raw_del, raw_act = set(), set()
    for oid, rec in _raw_records(SAMPLE_DIR, "users", "computers"):
        for ref in rec.get("AllowedToDelegate") or []:
            if isinstance(ref, dict) and ref.get("ObjectIdentifier"):
                raw_del.add((oid, str(ref["ObjectIdentifier"])))
        for ref in rec.get("AllowedToAct") or []:
            if isinstance(ref, dict) and ref.get("ObjectIdentifier"):
                raw_act.add((str(ref["ObjectIdentifier"]), oid))
    emitted_del = {(e["src"], e["dst"]) for e in graph.edges.values()
                   if e["rel"] == "ALLOWED_TO_DELEGATE"}
    emitted_act = {(e["src"], e["dst"]) for e in graph.edges.values()
                   if e["rel"] == "ALLOWED_TO_ACT"}
    assert raw_del == emitted_del == {
        ("S-1-5-21-2697957641-2271029196-387917394-2171",
         "S-1-5-21-2697957641-2271029196-387917394-1000")}
    assert raw_act == emitted_act == {
        ("S-1-5-21-3702535222-3822678775-2090119576-1169",
         "S-1-5-21-3702535222-3822678775-2090119576-1120")}


@requires_sample
def test_ace_inheritance_flag_propagates_verbatim(graph):
    """Every raw ACE emits principal --RIGHT--> record with the IsInherited
    flag carried onto the edge as `inherited` (bool, never dropped, never
    flipped). Concrete sample ACEs (objectids):
      - ...-512 (DOMAIN ADMINS) OWNS ...-1103 (JONAS-TEST-MS01), IsInherited=False;
      - ...-526 (KEY ADMINS) ADD_KEY_CREDENTIAL_LINK ...-1103, IsInherited=True;
      - ...-527 (ENTERPRISE KEY ADMINS) ADD_KEY_CREDENTIAL_LINK ...-1103,
        IsInherited=True.
    """
    from sever.etl.ad_collectors import _right_to_rel
    # (principal, oid, rel, inherited) pairs. Self-ACEs (PrincipalSID == own
    # oid) are excluded from raw: the parser drops self-loops BY POLICY (a
    # self-loop never changes reachability — 32 such group self-ACEs exist in
    # the sample, e.g. ENTERPRISE ADMINS WriteDacl-on-itself).
    raw_pairs = set()
    for oid, rec in _raw_records(SAMPLE_DIR):
        for ace in rec.get("Aces") or []:
            if not isinstance(ace, dict):
                continue
            principal = str(ace.get("PrincipalSID"))
            if principal == oid:
                continue
            raw_pairs.add((principal, oid, _right_to_rel(str(ace.get("RightName"))),
                           bool(ace.get("IsInherited", False))))
    emitted_pairs = {(e["src"], e["dst"], e["rel"], e["props"]["inherited"])
                     for e in graph.edges.values() if "inherited" in e["props"]}
    assert emitted_pairs == raw_pairs, "emitted ACE edges differ from raw ACE set"
    jonas = "S-1-5-21-2697957641-2271029196-387917394-1103"
    da = "S-1-5-21-2697957641-2271029196-387917394-512"
    assert (da, jonas, "OWNS", False) in emitted_pairs
    assert ("S-1-5-21-2697957641-2271029196-387917394-526",
            jonas, "ADD_KEY_CREDENTIAL_LINK", True) in emitted_pairs
    assert ("S-1-5-21-2697957641-2271029196-387917394-527",
            jonas, "ADD_KEY_CREDENTIAL_LINK", True) in emitted_pairs
    # sample census: every emitted ACE edge carries a bool inherited flag
    assert all(isinstance(e["props"]["inherited"], bool)
               for e in graph.edges.values() if "inherited" in e["props"])


@requires_sample
def test_membership_edges_match_raw_members_and_primary_groups(graph):
    """Raw Members refs -> non-primary MEMBER_OF member->group; raw
    PrimaryGroupSID -> primary MEMBER_OF. Concrete: ANDY (...-2187) in
    PHANTOM.CORP-S-1-5-32-550 (PRINT OPERATORS); computers' PrimaryGroupSID
    ...-515 (DOMAIN COMPUTERS)."""
    raw_members, raw_primary = set(), set()
    for oid, rec in _raw_records(SAMPLE_DIR):
        for m in rec.get("Members") or []:
            if isinstance(m, dict) and m.get("ObjectIdentifier"):
                raw_members.add((str(m["ObjectIdentifier"]), oid))
        if rec.get("PrimaryGroupSID"):
            raw_primary.add((oid, str(rec["PrimaryGroupSID"])))
    mo = [e for e in graph.edges.values() if e["rel"] == "MEMBER_OF"]
    emitted_members = {(e["src"], e["dst"]) for e in mo if not e["props"].get("primary")}
    emitted_primary = {(e["src"], e["dst"]) for e in mo if e["props"].get("primary")}
    assert emitted_members == raw_members and len(raw_members) == 161
    assert emitted_primary == raw_primary and len(raw_primary) == 131
    assert ("S-1-5-21-2697957641-2271029196-387917394-2187",
            "PHANTOM.CORP-S-1-5-32-550") in emitted_members
    for comp in ("S-1-5-21-2697957641-2271029196-387917394-1103",
                 "S-1-5-21-2697957641-2271029196-387917394-2174",
                 "S-1-5-21-2697957641-2271029196-387917394-2167"):
        assert (comp, "S-1-5-21-2697957641-2271029196-387917394-515") in emitted_primary


@requires_sample
def test_published_on_matches_raw_enabled_cert_templates(graph):
    """EnabledCertTemplates on EnterpriseCA records -> PUBLISHED_ON
    template->CA. Concrete: templates 4240FC96-5DC1-4B4D-A141-23FC0D59C0A0
    (ESC13TEMPLATE), 8200E71C-88F3-4A9E-9912-4FBE0F97D2CB (ESC14) and
    96B6A107-47FD-4A98-B183-B6EFCD9E4467 (ABUSABLETEMPLATE) publish on CA
    CDCA8CA4-69D6-4488-87AE-F8F507D53DB9 (PHANTOM-DC01-CA)."""
    raw = set()
    for oid, rec in _raw_records(SAMPLE_DIR, "enterprisecas"):
        for t in rec.get("EnabledCertTemplates") or []:
            if isinstance(t, dict) and t.get("ObjectIdentifier"):
                raw.add((str(t["ObjectIdentifier"]), oid))
    emitted = {(e["src"], e["dst"]) for e in graph.edges.values()
               if e["rel"] == "PUBLISHED_ON"}
    assert raw == emitted and len(emitted) == 86
    ca = "CDCA8CA4-69D6-4488-87AE-F8F507D53DB9"
    for tpl in ("4240FC96-5DC1-4B4D-A141-23FC0D59C0A0",
                "8200E71C-88F3-4A9E-9912-4FBE0F97D2CB",
                "96B6A107-47FD-4A98-B183-B6EFCD9E4467"):
        assert (tpl, ca) in emitted


@requires_sample
def test_contained_by_matches_raw_containedby(graph):
    """Raw ContainedBy refs -> CONTAINED_BY record->parent. Concrete:
    JONAS-TEST-MS01 (...-1103) in COMPUTERS container
    2CADA56A-0451-4431-B0EE-001D47266554; ALICE-LAPTOP (...-2174) in OU
    2A2B238D-7CD4-45FD-964A-A402A9752B2E; SRV-SHARPHOUND (...-2167) in OU
    96B54890-3289-45CC-9B19-F46465ED6A56."""
    raw = set()
    for oid, rec in _raw_records(SAMPLE_DIR):
        cb = rec.get("ContainedBy")
        if isinstance(cb, dict) and cb.get("ObjectIdentifier"):
            raw.add((oid, str(cb["ObjectIdentifier"])))
    emitted = {(e["src"], e["dst"]) for e in graph.edges.values()
               if e["rel"] == "CONTAINED_BY"}
    assert raw == emitted
    assert ("S-1-5-21-2697957641-2271029196-387917394-1103",
            "2CADA56A-0451-4431-B0EE-001D47266554") in emitted
    assert ("S-1-5-21-2697957641-2271029196-387917394-2174",
            "2A2B238D-7CD4-45FD-964A-A402A9752B2E") in emitted
    assert ("S-1-5-21-2697957641-2271029196-387917394-2167",
            "96B54890-3289-45CC-9B19-F46465ED6A56") in emitted


@requires_sample
def test_unresolved_nodes_have_honest_origins(graph):
    """The 9 unresolved nodes are honest collector references, each with at
    least one incident edge (the unresolved-principal invariant's proof set):
      - CN=ENTERPRISE ADMINS,OU=GROUPS,... (a DN-shaped Member ref on GHOST's
        groups — SharpHound resolved the cross-domain principal by DN);
      - S-1-5-32 (the BUILTIN container: ContainedBy parent of every
        prefixed/builtin group, never itself collected);
      - ...-2213 (an uncollected PHANTOM user holding Enroll on cert templates);
      - S-1-5-21-428050025-...-1000 (a foreign domain DC, Enroll on a WRAITH CA);
      - five GUID containers (ContainedBy parents only the 111414 snapshot lists).
    """
    unres = {oid for oid, n in graph.nodes.items() if n["props"].get("unresolved")}
    assert len(unres) == 9
    assert "CN=ENTERPRISE ADMINS,OU=GROUPS,OU=TIER0,DC=PHANTOM,DC=CORP" in unres
    assert "S-1-5-32" in unres
    assert "S-1-5-21-2697957641-2271029196-387917394-2213" in unres
    assert "S-1-5-21-428050025-2300188546-864808017-1000" in unres
    for oid in unres:
        incident = [e for e in graph.edges.values() if e["src"] == oid or e["dst"] == oid]
        assert incident, f"unresolved node {oid} has no incident edge — orphan placeholder"
        # unresolved nodes never pretend to be resolved
        assert graph.nodes[oid]["props"]["unresolved"] is True


@requires_sample
def test_sample_has_no_sid_history_or_spn_target_data():
    """Documents a coverage fact: the CE sample's HasSIDHistory and SPNTargets
    keys exist on every user/computer record but every list is EMPTY — so those
    derivation branches are pinned by the synthetic tests below
    (test_sid_history_and_spn_target_derivation_correct), not by sample data.
    If the sample ever changes, this fails and forces re-verification."""
    n_sh = sum(1 for _, rec in _raw_records(SAMPLE_DIR, "users", "computers")
               if rec.get("HasSIDHistory"))
    n_spn = sum(1 for _, rec in _raw_records(SAMPLE_DIR, "users", "computers")
                if rec.get("SPNTargets"))
    assert (n_sh, n_spn) == (0, 0)


# ---- (c) adversarial/hostile collector inputs (DB-free, always run) ----


def test_hostile_doc_not_object_fails_loud(tmp_path):
    (tmp_path / "20240101000000_users.json").write_text('["not", "an", "object"]', encoding="utf-8")
    with pytest.raises(ValueError, match="top level must be a JSON object"):
        parse_ad_dir(tmp_path)


def test_hostile_data_not_a_list_fails_loud(tmp_path):
    for bad in ('{"data": {"S-u1": {}}}', '{"data": "users everywhere"}', '{"data": 42}'):
        (tmp_path / "20240101000000_users.json").write_text(bad, encoding="utf-8")
        with pytest.raises(ValueError, match="'data' must be a list"):
            parse_ad_dir(tmp_path)
        (tmp_path / "20240101000000_users.json").unlink()


def test_hostile_data_null_parses_to_zero_records(tmp_path):
    (tmp_path / "20240101000000_users.json").write_text('{"data": null}', encoding="utf-8")
    g = parse_ad_dir(tmp_path)
    assert g.nodes == {} and g.edges == {}
    _assert_invariants(g)


def test_hostile_non_dict_records_are_counted(tmp_path):
    (tmp_path / "20240101000000_users.json").write_text(json.dumps(
        {"data": ["a bare string", 42, None, {"ObjectIdentifier": "S-u1",
                                              "Properties": {"name": "u1"}}]}),
        encoding="utf-8")
    g = parse_ad_dir(tmp_path)
    assert set(g.nodes) == {"S-u1"}
    assert g.stats["skipped"] == {"malformed_record": 6}  # 3 bad records x 2 passes
    _assert_invariants(g)


def test_hostile_properties_wrong_type_is_counted(tmp_path):
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [
            {"ObjectIdentifier": "S-u1", "Properties": "not-a-dict"},   # string props
            {"ObjectIdentifier": "S-u2", "Properties": ["also", "bad"]},  # list props
            {"ObjectIdentifier": "S-u3"},                                 # no props key at all
        ]},
    )
    g = parse_ad_dir(tmp_path)
    assert set(g.nodes) == {"S-u1", "S-u2", "S-u3"}
    assert g.nodes["S-u1"]["props"] == {"owned": False}
    assert g.nodes["S-u3"]["props"] == {"owned": False}
    assert g.stats["skipped"] == {"malformed_properties": 4}  # 2 records x 2 passes
    assert g.edges == {}
    _assert_invariants(g)


def test_hostile_string_where_list_expected_never_iterates_chars(tmp_path):
    """The killer hostile case: a STRING in a list-typed field used to be
    iterated character-by-character — HasSIDHistory: "S-1" emitted one
    garbage HAS_SID_HISTORY edge per character. Now every wrong-typed field is
    counted and yields nothing."""
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [{
            "ObjectIdentifier": "S-u1", "Properties": {"name": "u1"},
            "Aces": "GenericAll",
            "Members": "S-1-5-21-x",
            "HasSIDHistory": "S-1-5-21-x-999",
            "SPNTargets": "MSSQLSvc/srv:1433",
            "AllowedToDelegate": "S-target",
            "AllowedToAct": "S-actor",
            "LocalGroups": "S-1-5-32-544",
            "Trusts": "GHOST.CORP",
            "EnabledCertTemplates": "tpl-guid",
        }]},
    )
    g = parse_ad_dir(tmp_path)
    assert g.edges == {}, f"garbage edges emitted: {list(g.edges)[:5]}"
    assert set(g.nodes) == {"S-u1"}
    sk = g.stats["skipped"]
    # edge-derivation counters fire once (the node pass never touches them)
    assert sk == {
        "malformed_aces": 1, "malformed_members": 1, "malformed_hassidhistory": 1,
        "malformed_spntargets": 1, "malformed_allowedtodelegate": 1,
        "malformed_allowedtoact": 1, "malformed_localgroups": 1,
        "malformed_trusts": 1, "malformed_enabledcerttemplates": 1,
    }
    _assert_invariants(g)


def test_sid_history_and_spn_target_derivation_correct(tmp_path):
    """The two zero-sample-coverage branches pinned synthetically: valid
    HasSIDHistory SIDs -> HAS_SID_HISTORY user->oldsid with an unresolved User
    node; valid SPNTargets -> HAS_SPN_TARGET user->computer endpoint with the
    service prop; malformed entries are counted, never garbage."""
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [{
            "ObjectIdentifier": "S-u1", "Properties": {"name": "u1"},
            "HasSIDHistory": ["S-ghost-old", {"ObjectIdentifier": "S-dict-ref"}, 17, ""],
            "SPNTargets": [
                {"EndpointAddress": "S-comp", "Service": "MSSQLSvc/srv:1433"},
                {"Service": "missing-endpoint"},
                {"EndpointAddress": {"nested": True}},
                "not-a-dict",
                {"EndpointAddress": ""},
            ],
        }]},
    )
    g = parse_ad_dir(tmp_path)
    _assert_invariants(g)
    sh = [e for e in g.edges.values() if e["rel"] == "HAS_SID_HISTORY"]
    assert {(e["src"], e["dst"]) for e in sh} == {("S-u1", "S-ghost-old")}
    assert g.nodes["S-ghost-old"]["label"] == "User"
    assert g.nodes["S-ghost-old"]["props"].get("unresolved") is True
    spn = [e for e in g.edges.values() if e["rel"] == "HAS_SPN_TARGET"]
    assert {(e["src"], e["dst"], e["props"].get("service")) for e in spn} == {
        ("S-u1", "S-comp", "MSSQLSvc/srv:1433")}
    assert g.nodes["S-comp"]["label"] == "Computer"
    assert g.stats["skipped"] == {"sidhistory_malformed_entry": 3,
                                  "spntarget_malformed_entry": 4}


def test_hostile_ace_wrong_types_are_counted(tmp_path):
    _collector_file(
        tmp_path, "20240101000000_computers.json",
        {"data": [{
            "ObjectIdentifier": "S-comp", "Properties": {"name": "srv01"},
            "Aces": [
                "a bare string ace",
                {"PrincipalSID": {"sid": True}, "RightName": "GenericAll"},
                {"PrincipalSID": "S-p1", "RightName": 42},
                {"PrincipalSID": "S-p2", "RightName": "GenericAll"},
            ],
        }]},
    )
    g = parse_ad_dir(tmp_path)
    _assert_invariants(g)
    edges = [(e["src"], e["dst"], e["rel"]) for e in g.edges.values()]
    assert edges == [("S-p2", "S-comp", "GENERIC_ALL")]
    assert g.stats["skipped"] == {
        "ace_malformed_entry": 1, "ace_malformed_fields": 2}


def test_hostile_primary_group_sid_and_containedby_wrong_shapes(tmp_path):
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [
            {"ObjectIdentifier": "S-a", "PrimaryGroupSID": {"sid": True},
             "ContainedBy": "OU=not-a-ref"},
            {"ObjectIdentifier": "S-b", "PrimaryGroupSID": 12345,
             "ContainedBy": {"ObjectIdentifier": {"nested": True}}},
            {"ObjectIdentifier": "S-c", "PrimaryGroupSID": "S-g1",
             "ContainedBy": {"ObjectIdentifier": "CN=Parent", "ObjectType": "Container"}},
        ]},
    )
    g = parse_ad_dir(tmp_path)
    _assert_invariants(g)
    edges = {(e["src"], e["dst"], e["rel"]) for e in g.edges.values()}
    assert edges == {("S-c", "S-g1", "MEMBER_OF"), ("S-c", "CN=Parent", "CONTAINED_BY")}
    # S-g1 materializes unresolved; no garbage "{'sid': True}"-style node ids
    assert "S-g1" in g.nodes and g.nodes["S-g1"]["props"].get("unresolved")
    assert g.stats["skipped"] == {
        "malformed_primarygroupsid": 2, "malformed_containedby": 2}


def test_hostile_localgroups_wrong_shapes(tmp_path):
    _collector_file(
        tmp_path, "20240101000000_computers.json",
        {"data": [{
            "ObjectIdentifier": "S-comp", "Properties": {"name": "srv01"},
            "LocalGroups": [
                "not-a-dict",
                {"Name": "no-oid"},
                {"ObjectIdentifier": "S-1-5-32-544", "Results": {"member": "dict-not-list"}},
                {"ObjectIdentifier": "S-1-5-32-545", "Results": [  # non-admin RID: inert
                    {"ObjectIdentifier": "S-rdp-user", "ObjectType": "User"}]},
                {"ObjectIdentifier": "S-1-5-32-544", "Results": [
                    "a bare string member",
                    {"ObjectIdentifier": {"sid": True}},
                    {"ObjectIdentifier": "S-real-admin", "ObjectType": "User"},
                ]},
            ],
        }]},
    )
    g = parse_ad_dir(tmp_path)
    _assert_invariants(g)
    admin = [e for e in g.edges.values() if e["rel"] == "ADMIN_TO"]
    assert {(e["src"], e["dst"]) for e in admin} == {("S-real-admin", "S-comp")}
    assert g.nodes["S-real-admin"]["props"].get("unresolved") is True
    # RID -545 (non-admin) local group is skipped wholesale — BH semantics:
    # no ADMIN_TO edge AND no member placeholder node (its members are all
    # collected domain principals anyway)
    assert "S-rdp-user" not in g.nodes
    assert not any(e["src"] == "S-rdp-user" for e in g.edges.values())
    assert g.stats["skipped"] == {
        "localgroup_malformed_entry": 2, "localgroup_malformed_results": 1,
        "localgroup_malformed_member": 2}


def test_hostile_trusts_wrong_shapes_and_nonprimitive_props(tmp_path):
    _collector_file(
        tmp_path, "20240101000000_domains.json",
        {"data": [{
            "ObjectIdentifier": "S-dom", "Properties": {"name": "DOM"},
            "Trusts": [
                "not-a-dict",
                {"TargetDomainName": "NO-SID.CORP"},
                {"TargetDomainSid": {"sid": True}},
                {"TargetDomainSid": "S-external", "TargetDomainName": {"name": ["nested"]},
                 "TrustDirection": {"direction": True}, "TrustType": "External"},
            ],
        }]},
    )
    g = parse_ad_dir(tmp_path)
    _assert_invariants(g)
    assert g.stats["skipped"] == {
        "trust_malformed_entry": 1, "trust_missing_target_sid": 2}
    tb = [e for e in g.edges.values() if e["rel"] == "TRUSTED_BY"]
    assert len(tb) == 1 and (tb[0]["src"], tb[0]["dst"]) == ("S-dom", "S-external")
    # non-primitive trust props are canonical JSON strings on the edge —
    # FalkorDB rejects non-primitive map values, so this must never be a dict
    assert isinstance(tb[0]["props"]["direction"], str)
    assert json.loads(tb[0]["props"]["direction"]) == {"direction": True}
    assert g.nodes["S-external"]["props"].get("external") is True


def test_hostile_missing_every_optional_field_parses_clean(tmp_path):
    (tmp_path / "20240101000000_users.json").write_text(
        json.dumps({"data": [{"ObjectIdentifier": "S-bare"}]}), encoding="utf-8")
    g = parse_ad_dir(tmp_path)
    assert set(g.nodes) == {"S-bare"}
    assert g.nodes["S-bare"]["props"] == {"owned": False}
    assert g.edges == {} and g.stats["skipped"] == {}
    _assert_invariants(g)


def test_hostile_null_and_empty_prop_values_dropped_not_stored(tmp_path):
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [{"ObjectIdentifier": "S-u1", "Properties": {
            "name": None, "description": "", "enabled": False, "level": 0,
        }}]},
    )
    g = parse_ad_dir(tmp_path)
    assert g.nodes["S-u1"]["props"] == {"enabled": False, "level": 0, "owned": False}
    _assert_invariants(g)


def test_hostile_unicode_names_round_trip(tmp_path):
    name = "Ünïcödé 嵐 🕵️‍♀️ émoji"
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [{"ObjectIdentifier": "S-ü", "Properties": {"name": name}}]},
    )
    g1, g2 = parse_ad_dir(tmp_path), parse_ad_dir(tmp_path)
    assert g1.nodes["S-ü"]["props"]["name"] == name
    assert _edge_hash(g1) == _edge_hash(g2)
    _assert_invariants(g1)


def test_hostile_duplicate_objectids_across_files_single_deterministic_node(tmp_path):
    """Same objectid as a Group in one file and a User in another: exactly one
    node, label from the first-seen file type in the sorted walk (groups before
    users), props merged deterministically."""
    _collector_file(
        tmp_path, "20240101000000_groups.json",
        {"data": [{"ObjectIdentifier": "S-dup", "Properties": {"name": "grp",
                                                                "description": "from-group"},
                   "Members": [{"ObjectIdentifier": "S-m", "ObjectType": "User"}]}]},
    )
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [
            {"ObjectIdentifier": "S-dup", "Properties": {"name": "usr",
                                                         "title": "from-user"}},
            {"ObjectIdentifier": "S-dup", "Properties": {"name": "usr",
                                                          "title": "later-dupe"}},
        ]},
    )
    g1, g2 = parse_ad_dir(tmp_path), parse_ad_dir(tmp_path)
    assert set(g1.nodes) == {"S-dup", "S-m"}
    assert g1.nodes["S-dup"]["label"] == "Group"  # groups file sorts first
    assert g1.nodes["S-dup"]["props"]["name"] == "grp"
    assert g1.nodes["S-dup"]["props"]["title"] == "from-user"  # first wins, deterministically
    assert _edge_hash(g1) == _edge_hash(g2)
    _assert_invariants(g1)


def test_hostile_self_referencing_sids_never_emit_self_loops(tmp_path):
    """A record referencing its own SID in every branch: no self-loop edge of
    any kind, node intact, invariant holds (self-ACLs are presence, not
    privilege — and a self-loop can never change reachability)."""
    me = "S-me"
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [{
            "ObjectIdentifier": me, "Properties": {"name": "narcissist"},
            "Aces": [{"PrincipalSID": me, "RightName": "GenericAll", "IsInherited": True}],
            "PrimaryGroupSID": me,
            "ContainedBy": {"ObjectIdentifier": me},
            "HasSIDHistory": [me],
            "SPNTargets": [{"EndpointAddress": me, "Service": "x"}],
            "AllowedToDelegate": [{"ObjectIdentifier": me}],
            "AllowedToAct": [{"ObjectIdentifier": me}],
        }]},
    )
    _collector_file(
        tmp_path, "20240101000000_computers.json",
        {"data": [{
            "ObjectIdentifier": "S-comp2", "Properties": {"name": "c2"},
            "LocalGroups": [{"ObjectIdentifier": "DOM-S-1-5-32-544",
                             "Results": [{"ObjectIdentifier": "S-comp2",
                                          "ObjectType": "Computer"}]}],
        }]},
    )
    g = parse_ad_dir(tmp_path)
    assert not any(e["src"] == e["dst"] for e in g.edges.values()), "self-loop edge emitted"
    assert set(g.nodes) == {"S-me", "S-comp2"}
    assert g.nodes[me]["label"] == "User"
    assert g.edges == {}
    _assert_invariants(g)


def test_hostile_one_megabyte_strings_parse_clean_and_verbatim(tmp_path):
    """A 1MB name is the collector's own data: parsed verbatim (no silent
    truncation — that would be corruption), deterministic, invariant-safe."""
    big = "X" * (1024 * 1024)
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [{"ObjectIdentifier": "S-big", "Properties": {"name": big}},
                  {"ObjectIdentifier": "S-u2", "Properties": {"name": "u2"},
                   "Aces": [{"PrincipalSID": big, "RightName": "GenericAll"}]}]},
    )
    g1, g2 = parse_ad_dir(tmp_path), parse_ad_dir(tmp_path)
    assert g1.nodes["S-big"]["props"]["name"] == big
    assert g1.nodes[big]["props"].get("unresolved") is True  # honest placeholder
    assert _edge_hash(g1) == _edge_hash(g2)
    _assert_invariants(g1)


def test_hostile_deeply_nested_properties_parse_to_json_string(tmp_path):
    deep = {"n": 0}
    for _ in range(150):
        deep = {"n": deep}
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [{"ObjectIdentifier": "S-deep", "Properties": {"name": "deep",
                                                                "blob": deep}}]},
    )
    g = parse_ad_dir(tmp_path)
    assert isinstance(g.nodes["S-deep"]["props"]["blob"], str)  # jsonified, primitive
    assert json.loads(g.nodes["S-deep"]["props"]["blob"]) == deep
    _assert_invariants(g)


def test_hostile_unicode_rel_rejected_loud_at_batch_boundary(tmp_path):
    """An ACE RightName outside the identifier charset parses (it is data) but
    is rejected with a clear ValueError at the ONLY load path into Cypher —
    never silently interpolated into a query."""
    _collector_file(
        tmp_path, "20240101000000_users.json",
        {"data": [
            {"ObjectIdentifier": "S-u1", "Properties": {"name": "u1"},
             "Aces": [{"PrincipalSID": "S-p", "RightName": "ВсёДоступ"}]},
        ]},
    )
    g = parse_ad_dir(tmp_path)
    assert any(e["rel"] == "ВСЁДОСТУП" for e in g.edges.values())
    with pytest.raises(ValueError, match="unsafe relationship type"):
        build_batches(g)


def test_sessions_and_computer_quirk_fields_are_inert(tmp_path):
    """The CE sample's computer-record quirks (all 34 computers carry these)
    must neither crash the parser nor leak into the graph. Sessions are
    presence data — deliberately NOT derived (documented in ad_collectors):
    zero session edges exist anywhere in the product's model."""
    _collector_file(
        tmp_path, "20240101000000_computers.json",
        {"data": [{
            "ObjectIdentifier": "S-comp", "Properties": {"name": "DC01"},
            "Sessions": {"Results": [], "Collected": False, "FailureReason": None},
            "PrivilegedSessions": {"Results": [
                {"UserSID": "S-admin", "ComputerSID": "S-comp"},
                {"UserSID": "S-admin2", "ComputerSID": "S-comp"},
            ], "Collected": True, "FailureReason": None},
            "RegistrySessions": {"Results": [{"UserSID": "S-admin",
                                              "ComputerSID": "S-comp"}]},
            "UserRights": [{"Privilege": "SeRemoteInteractiveLogonRight",
                            "Results": [{"ObjectIdentifier": "DOM-S-1-5-32-544",
                                         "ObjectType": "Group"}],
                            "LocalNames": [], "Collected": True, "FailureReason": None}],
            "Status": {"Connectable": False, "Error": "PwdLastSetOutOfRange"},
            "DCRegistryData": {"CertificateMappingMethods": None},
            "DumpSMSAPassword": [{"ObjectIdentifier": "S-gmsa", "ObjectType": "Base"}],
        }]},
    )
    g = parse_ad_dir(tmp_path)
    _assert_invariants(g)
    # no session/user-rights/status data became edges or props
    assert g.edges == {}
    assert set(g.nodes) == {"S-comp"}
    props = g.nodes["S-comp"]["props"]
    assert props["dumpsmsapassword"] is True  # the one deliberate coercion
    for leaked in ("sessions", "privilegedsessions", "registrysessions",
                   "userrights", "status", "dcregistrydata"):
        assert leaked not in props
    # determinism with the quirk fields present
    assert _edge_hash(g) == _edge_hash(parse_ad_dir(tmp_path))


def test_no_dangling_endpoints_after_each_hostile_parse(tmp_path):
    """The unresolved-principal invariant as an always-run DB-free probe: build
    one dir per hostile shape class and assert every edge endpoint resolves."""
    shapes = {
        "weird-refs": {"data": [{
            "ObjectIdentifier": "S-h", "Properties": {"name": "h"},
            "Aces": [{"PrincipalSID": "S-ghost-ace", "RightName": "GenericAll"}],
            "Members": [{"ObjectIdentifier": "S-ghost-member", "ObjectType": "User"}],
            "AllowedToDelegate": [{"ObjectIdentifier": "S-ghost-tgt",
                                   "ObjectType": "Computer"}],
            "AllowedToAct": [{"ObjectIdentifier": "S-ghost-act",
                               "ObjectType": "Computer"}],
            "LocalGroups": [{"ObjectIdentifier": "D-S-1-5-32-544",
                             "Results": [{"ObjectIdentifier": "S-ghost-adm",
                                          "ObjectType": "User"}]}],
            "SPNTargets": [{"EndpointAddress": "S-ghost-spn", "Service": "x"}],
            "HasSIDHistory": ["S-ghost-hist"],
            "Trusts": [{"TargetDomainSid": "S-foreign-dom",
                        "TargetDomainName": "GHOST.CORP",
                        "TrustDirection": "Bidirectional", "TrustType": "External"}],
        }]},
        "mixed-good-bad": {"data": [
            {"ObjectIdentifier": "S-ok", "Properties": {"name": "ok"},
             "Aces": [{"PrincipalSID": "S-ghost-2", "RightName": "WriteDacl"}]},
            "junk-record",
            {"ObjectIdentifier": "", "Properties": {"name": "no-oid"}},
        ]},
    }
    for i, (name, doc) in enumerate(shapes.items()):
        d = tmp_path / name
        _collector_file(d, f"2024010100000{i}_users.json", doc)
        g = parse_ad_dir(d)
        ids = set(g.nodes)
        assert ids, f"{name}: nothing parsed"
        assert all(e["src"] in ids and e["dst"] in ids for e in g.edges.values()), name
        assert all(n["props"].get("unresolved") for n in g.nodes.values()
                   if n["objectid"].startswith("S-ghost"))
        # every parse is deterministic under hostile input too
        assert _edge_hash(g) == _edge_hash(parse_ad_dir(d))
