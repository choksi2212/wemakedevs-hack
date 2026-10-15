"""Emit FalkorDB-compatible Cypher UNWIND batches from a NormalizedGraph.

The same batch payloads feed the single production port (FalkorDB) and the
staged-batch tests — one emission path, one engine.
"""
from __future__ import annotations

from typing import Any

from sever.etl.ad_collectors import NormalizedGraph

DEFAULT_BATCH_ROWS = 1000


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
    """Group edges by relationship type -> UNWIND ... MATCH/MERGE batches."""
    by_rel: dict[str, list[dict[str, Any]]] = {}
    for edge in g.edges.values():
        row = {"src": edge["src"], "dst": edge["dst"], "props": edge["props"]}
        by_rel.setdefault(edge["rel"], []).append(row)

    batches: list[dict[str, Any]] = []
    for rel, rows in sorted(by_rel.items()):
        if rows and rows[0]["props"]:
            query = (
                f"UNWIND $rows AS e "
                f"MATCH (s {{objectid: e.src}}), (t {{objectid: e.dst}}) "
                f"MERGE (s)-[r:{rel} {{props_key: e.props_key}}]->(t) "
                f"SET r += e.props"
            )
            for row in rows:
                # canonical key so duplicate prop-variants stay distinct rels
                import json as _json

                row["props_key"] = _json.dumps(row["props"], sort_keys=True, default=str)
        else:
            query = (
                f"UNWIND $rows AS e "
                f"MATCH (s {{objectid: e.src}}), (t {{objectid: e.dst}}) "
                f"MERGE (s)-[:{rel}]->(t)"
            )
        for i in range(0, len(rows), batch_rows):
            batches.append({"kind": "edge", "query": query, "params": {"rows": rows[i : i + batch_rows]}})
    return batches


def build_batches(g: NormalizedGraph, batch_rows: int = DEFAULT_BATCH_ROWS) -> list[dict[str, Any]]:
    """Nodes first, then edges (FalkorDB creates indexes later; MERGE is idempotent)."""
    return node_batches(g, batch_rows) + edge_batches(g, batch_rows)
