"""Emit FalkorDB-compatible Cypher UNWIND batches from a NormalizedGraph.

The same batch payloads feed the single production port (FalkorDB) and the
staged-batch tests — one emission path, one engine.
"""
from __future__ import annotations

import json
import re
from typing import Any

from sever.etl.ad_collectors import NormalizedGraph

DEFAULT_BATCH_ROWS = 1000

# Cypher injection guard (audit/security): edge rels are interpolated into the
# query text below. AD-derived rels come from collector-data ACE RightName
# strings via _right_to_rel, i.e. data-file content — not a closed enum — so
# they must pass the same charset gate as the live mutation path
# (sever.core.falkor_port._valid_rel) before they touch a query template.
# [A-Za-z0-9_] carries no Cypher metacharacter, so a validated rel cannot
# escape the `-[r:{rel}]->` slot. Legit BloodHound/Entra rel types all match.
# \Z (not $): Python's $ also matches before a trailing newline.
_REL_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}\Z")


def _is_safe_rel(rel: str) -> bool:
    return bool(rel) and bool(_REL_TYPE_RE.match(rel))


def node_batches(g: NormalizedGraph, batch_rows: int = DEFAULT_BATCH_ROWS) -> list[dict[str, Any]]:
    """Group nodes by label -> UNWIND ... MERGE batches."""
    by_label: dict[str, list[dict[str, Any]]] = {}
    for node in g.nodes.values():
        row = {"objectid": node["objectid"], "props": node["props"]}
        by_label.setdefault(node["label"], []).append(row)

    batches: list[dict[str, Any]] = []
    for label, rows in sorted(by_label.items()):
        query = (
            f"UNWIND $rows AS r "
            f"MERGE (n:{label} {{objectid: r.objectid}}) "
            f"SET n += r.props"
        )
        for i in range(0, len(rows), batch_rows):
            batches.append({"kind": "node", "query": query, "params": {"rows": rows[i : i + batch_rows]}})
    return batches


def edge_batches(g: NormalizedGraph, batch_rows: int = DEFAULT_BATCH_ROWS) -> list[dict[str, Any]]:
    """Group edges by relationship type -> UNWIND ... MATCH/MERGE batches.

    A rel group may be MIXED: MEMBER_OF, for instance, carries prop-less
    Members-derived rows and prop-carrying PrimaryGroupSID-derived rows
    ({"primary": True}) in one group. The query shape is therefore chosen
    per SUB-BATCH, never from rows[0] alone: each rel group splits into a
    has-props and a no-props sub-batch so a prop-less first row can never
    select the no-props MERGE for prop-carrying rows (audit M65 — that
    shape silently dropped every later row's props at Cypher load, gated
    only on edge insertion order).
    """
    by_rel: dict[str, list[dict[str, Any]]] = {}
    for edge in g.edges.values():
        row = {"src": edge["src"], "dst": edge["dst"], "props": edge["props"]}
        by_rel.setdefault(edge["rel"], []).append(row)

    batches: list[dict[str, Any]] = []

    def _emit(rel: str, rows: list[dict[str, Any]], with_props: bool) -> None:
        if with_props:
            query = (
                f"UNWIND $rows AS e "
                f"MATCH (s {{objectid: e.src}}), (t {{objectid: e.dst}}) "
                f"MERGE (s)-[r:{rel} {{props_key: e.props_key}}]->(t) "
                f"SET r += e.props"
            )
            for row in rows:
                # canonical key so duplicate prop-variants stay distinct rels
                row["props_key"] = json.dumps(row["props"], sort_keys=True, default=str)
        else:
            query = (
                f"UNWIND $rows AS e "
                f"MATCH (s {{objectid: e.src}}), (t {{objectid: e.dst}}) "
                f"MERGE (s)-[:{rel}]->(t)"
            )
        for i in range(0, len(rows), batch_rows):
            batches.append({"kind": "edge", "query": query, "params": {"rows": rows[i : i + batch_rows]}})

    for rel, rows in sorted(by_rel.items()):
        if not _is_safe_rel(rel):
            # fail loud: a collector data file that produces a rel outside the
            # identifier charset is either corrupt or hostile — never load it.
            raise ValueError(
                f"unsafe relationship type in collector data (rejected before "
                f"Cypher interpolation): {rel!r}"
            )
        with_props = [row for row in rows if row["props"]]
        without_props = [row for row in rows if not row["props"]]
        if with_props:
            _emit(rel, with_props, True)
        if without_props:
            _emit(rel, without_props, False)
    return batches


def build_batches(g: NormalizedGraph, batch_rows: int = DEFAULT_BATCH_ROWS) -> list[dict[str, Any]]:
    """Nodes first, then edges (FalkorDB creates indexes later; MERGE is idempotent)."""
    return node_batches(g, batch_rows) + edge_batches(g, batch_rows)
