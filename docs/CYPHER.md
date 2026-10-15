# SEVER — The Cypher Queries the Product Depends On

Rule 10 requires publishing the exact queries. These are the **live-verified**
forms (every one executed against falkordb 6.0.0 during the build — receipts in
`docs/receipts_live_sever_demo.json`), maintained as module constants in
`sever/core/falkor_port.py`. `[:REL|…]` is the abusable traversal pattern from
`sever/core/jewels.py::cypher_traversal_pattern` — 30+ relationship types,
upper-bounded `*..12` (FalkorDB's shortestPath rejects lower bounds).

## Crown jewels

```cypher
MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
RETURN g.objectid AS objectid ORDER BY objectid
-- Entra jewels (hybrid estates):
MATCH (u:AZUser) WHERE u.name ENDS WITH '-GlobalAdministrator'
RETURN u.objectid AS objectid ORDER BY objectid
```

## Reachability (headline metric)

Count of owned principals with ≥1 path to any crown jewel. Computed as a
**per-pair existence check**: for every (owned, jewel) pair the agent runs the
tie-set procedure (`PATH_QUERY_TEMPLATE` in `sever/core/falkor_port.py`) and
counts the pair as reached when ≥1 row comes back — the procedure yields an
empty result when no path exists, which is what makes it safe to re-query on a
collapsed estate (the collapse receipts depend on exactly this):

```cypher
MATCH (o {objectid: $oid}), (t {objectid: $target})
CALL algo.SPpaths({sourceNode: o, targetNode: t, pathCount: 100}) YIELD path
RETURN path
```

## Attack path enumeration

Canonical demo path (milliseconds, live-measured):

```cypher
MATCH (o {objectid: $oid}), (t {objectid: $target})
WITH shortestPath((o)-[:MEMBER_OF|GENERIC_ALL|…*..12]->(t)) AS p
RETURN p
```

This canonical form is also the scoring input: edge frequency walks the
canonical path of every (owned → jewel) pair and counts per-edge occurrences
(`EDGE_FREQUENCY_STEP`).

Offline analysis mode enumerates tied shortest paths via the built-in procedure
(measured: cross-domain tie sets take 15–25s+ per pair — the live agent loop
uses the canonical form):

```cypher
MATCH (o {objectid: $oid}), (t {objectid: $target})
CALL algo.SPpaths({sourceNode: o, targetNode: t, pathCount: 100}) YIELD path
RETURN path
```

## The interdiction (human-gated)

```cypher
-- pre-check receipt: how many relationships will be removed
MATCH (s {objectid: $src})-[r:GENERIC_ALL]->(t {objectid: $dst})
RETURN count(r) AS n
-- execution — only after explicit human approval
MATCH (s {objectid: $src})-[r:GENERIC_ALL]->(t {objectid: $dst})
DELETE r
```

## Live mutation (finding application — F-003 grants an ACE mid-demo)

```cypher
MATCH (s {objectid: $src}), (t {objectid: $dst})
MERGE (s)-[r:GENERIC_ALL]->(t) SET r += $props RETURN count(r)
```

## Bulk ingestion (UNWIND batches — nodes then edges)

```cypher
UNWIND $rows AS r MERGE (n:User {objectid: r.objectid}) SET n += r.props
UNWIND $rows AS e MATCH (s {objectid: e.src}), (t {objectid: e.dst})
MERGE (s)-[r:MEMBER_OF {props_key: e.props_key}]->(t) SET r += e.props
```

## Engine quirks mapped during the build (all live-verified)

- `shortestPath` is only valid as a WITH/RETURN expression, not `MATCH p = …`
- shortestPath hop ranges must be upper-bounded (`*..N`, no lower bound)
- `algo.SPpaths` config keys are `sourceNode`/`targetNode`; its procedure paths
  carry raw integer node ids on edges (parsed via ordered index-zip)
- property values must be primitives or primitive arrays (list-typed collector
  fields are coerced to booleans at ingest)
- the shipped container default query timeout is low — `TIMEOUT_DEFAULT 0`
  can be enabled via the commented `FALKORDB_ARGS` environment block in
  `docker-compose.yml` (only needed for long cross-domain tie-set analysis);
  the client already passes explicit per-query timeouts (up to 60s for
  path/reachability queries), so the product needs no tuning out of the box
