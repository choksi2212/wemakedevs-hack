"""Hostile BloodHound collector data vs the Cypher emission path (audit3).

Engine-free. A hostile sample JSON carries Cypher metacharacters in EVERY
string field (objectid, node properties, ACE principals, membership refs,
trust names, SPN targets, local-group names). The contract:

- every derived rel type must pass the identifier charset gate (hostile
  RightName values fail LOUD, refusing the whole load);
- every remaining hostile string — objectids and props — must ride through
  ``UNWIND $rows`` parameters (JSON-escaped by the client's params header)
  and NEVER appear in the query text;
- the naive f-string counterfactual (the same data interpolated into query
  TEXT) demonstrably breaks out — documenting exactly why the parameter
  binding is load-bearing.
"""
from __future__ import annotations

import json
import re

import pytest

from sever.etl.ad_collectors import parse_ad_dir
from sever.etl.cypher_batches import build_batches, edge_batches

# one hostile marker per metacharacter class, all machine-detectable
HOSTILE_FIELDS = {
    "brace": "X}]->(n) DETACH DELETE n //",
    "quote": "Y' RETURN 1 //",
    "dquote": 'Z" RETURN 1 //',
    "backtick": "` MATCH (n) DETACH DELETE n //",
    "dollar": "$dst RETURN 1",
    "comment": "W// DETACH DELETE n",
    "semicolon": "Q'; DROP GRAPH sever_demo; --",
    "bracket": "[*0..12] RETURN 1",
    "colon": ":MEMBER_OF {objectid: $x}",
}
ALL_HOSTILE = list(HOSTILE_FIELDS.values())


def _write_sample(dirname, *, hostile_right: bool = True):
    d = dirname
    d.mkdir(parents=True, exist_ok=True)
    mark = HOSTILE_FIELDS["brace"]
    users = {
        "data": [{
            "ObjectIdentifier": mark,
            "Properties": {
                "name": HOSTILE_FIELDS["quote"],
                "domain": HOSTILE_FIELDS["dollar"],
                "description": HOSTILE_FIELDS["comment"],
                "distinguishedname": HOSTILE_FIELDS["semicolon"],
            },
            "Aces": [{
                "PrincipalSID": HOSTILE_FIELDS["backtick"],
                "PrincipalType": "User",
                "RightName": "GenericAll}]->(n) DETACH DELETE n //" if hostile_right else "GenericAll",
                "IsInherited": False,
            }],
            "SPNTargets": [{
                "EndpointAddress": HOSTILE_FIELDS["bracket"],
                "Service": "host/" + HOSTILE_FIELDS["colon"],
            }],
        }],
        "meta": {"type": "users", "version": 6},
    }
    groups = {
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1-999-512",  # a crown-jewel-shaped SID (Domain Admins)
            "Properties": {"name": HOSTILE_FIELDS["dquote"], "domain": "evil"},
            "Members": [
                {"ObjectIdentifier": mark, "ObjectType": "User"},
                {"ObjectIdentifier": HOSTILE_FIELDS["quote"], "ObjectType": "User"},
            ],
            "Aces": [{
                "PrincipalSID": HOSTILE_FIELDS["dollar"],
                "PrincipalType": "User",
                "RightName": "WriteDacl",
            }],
        }],
        "meta": {"type": "groups", "version": 6},
    }
    computers = {
        "data": [{
            "ObjectIdentifier": "CN=DC01," + HOSTILE_FIELDS["quote"],
            "Properties": {"name": "DC01." + HOSTILE_FIELDS["colon"], "os": HOSTILE_FIELDS["comment"]},
            "LocalGroups": [{
                "ObjectIdentifier": "S-1-5-21-1-999-544",
                "Name": HOSTILE_FIELDS["semicolon"],
                "Results": [{"ObjectIdentifier": mark, "ObjectType": "User"}],
            }],
            "ContainedBy": {"ObjectIdentifier": HOSTILE_FIELDS["dollar"], "ObjectType": "Container"},
        }],
        "meta": {"type": "computers", "version": 6},
    }
    (d / "20240305110018_users.json").write_text(json.dumps(users), encoding="utf-8")
    (d / "20240305110018_groups.json").write_text(json.dumps(groups), encoding="utf-8")
    (d / "20240305110018_computers.json").write_text(json.dumps(computers), encoding="utf-8")


def test_hostile_right_name_fails_loud_before_any_query(tmp_path):
    """A hostile ACE RightName cannot become a safe rel type (charset gate)
    — the whole load refuses rather than interpolating it."""
    _write_sample(tmp_path, hostile_right=True)
    g = parse_ad_dir(tmp_path)
    with pytest.raises(ValueError, match="unsafe relationship type"):
        edge_batches(g)


def test_hostile_props_ride_as_params_never_in_query_text(tmp_path):
    """The loadable hostile sample: legit RightNames, hostile everything
    else. Every batch query must be byte-clean of hostile metacharacters;
    every hostile value must be present (intact) in the parameter rows."""
    _write_sample(tmp_path, hostile_right=False)
    g = parse_ad_dir(tmp_path)
    batches = build_batches(g)

    assert batches
    for b in batches:
        assert "$rows" in b["query"], b["query"]
        for hostile in ALL_HOSTILE:
            assert hostile not in b["query"], (b["kind"], hostile)
        # the query text is ONLY the fixed template plus the validated rel name
        assert "ObjectIdentifier" not in b["query"]
        if b["kind"] == "edge":
            # the ONLY data-derived bytes in the query are the rel type, which
            # must be one of the charset-validated rels derived from this sample
            m = re.search(r"MERGE \(s\)-\[r?:([A-Za-z0-9_]+)", b["query"])
            assert m and m.group(1) in {
                "GENERIC_ALL", "WRITE_DACL", "MEMBER_OF", "ADMIN_TO",
                "CONTAINED_BY", "HAS_SPN_TARGET",
            }, b["query"]

    # and the hostile strings are all in the params, byte-intact
    def _strings(o):
        if isinstance(o, dict):
            for v in o.values():
                yield from _strings(v)
        elif isinstance(o, list):
            for v in o:
                yield from _strings(v)
        elif isinstance(o, str):
            yield o

    param_strings = [s for b in batches for s in _strings(b["params"])]
    for hostile in ALL_HOSTILE:
        assert any(hostile in s for s in param_strings), hostile


def test_naive_fstring_counterfactual_would_break_out(tmp_path):
    """Why parameter binding is load-bearing: the same hostile data
    interpolated into the query TEXT (the naive f-string implementation)
    escapes the MERGE clause — this is the exact payload that would have
    worked pre-guard."""
    _write_sample(tmp_path, hostile_right=False)
    g = parse_ad_dir(tmp_path)
    node = next(iter(g.nodes.values()))
    edge = next(iter(g.edges.values()))
    naive_node_query = (
        f"MERGE (n:{node['label']} {{objectid: '{node['objectid']}'}}) "
        f"SET n += {node['props']}"
    )
    naive_edge_query = (
        f"MATCH (s {{objectid: '{edge['src']}'}}), (t {{objectid: '{edge['dst']}'}}) "
        f"MERGE (s)-[:{edge['rel']}]->(t) SET r += {edge['props']}"
    )
    for naive in (naive_node_query, naive_edge_query):
        # at least one hostile marker escapes the f-string literal context,
        # and the quote balance is broken by the payload's quotes
        assert any(h in naive for h in ALL_HOSTILE), naive
        assert naive.count("'") >= 3
    # while the real emission keeps every hostile byte out of the query text
    for b in build_batches(g):
        for hostile in ALL_HOSTILE:
            assert hostile not in b["query"]


def test_parse_survives_hostile_data_and_keeps_rels_in_vocabulary(tmp_path):
    """Even with hostile data files, every EMITTED rel type stays inside the
    safe identifier charset (the gate runs on emission regardless of input)."""
    _write_sample(tmp_path, hostile_right=False)
    g = parse_ad_dir(tmp_path)
    assert g.stats["node_count"] > 0 and g.stats["edge_count"] > 0
    for edge in g.edges.values():
        if edge["rel"] not in ("MEMBER_OF", "CONTAINED_BY", "HAS_SPN_TARGET", "ADMIN_TO",
                               "GENERIC_ALL", "WRITE_DACL"):
            pytest.fail(f"unexpected rel: {edge['rel']!r}")
