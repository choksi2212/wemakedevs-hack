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

Count of owned principals with ≥1 shortest path to any crown jewel. FalkorDB
supports `shortestPath` **only as a WITH-clause expression**, so reachability is
per-pair existence:

```cypher
MATCH (o {objectid: $oid}), (t {objectid: $target})
WITH shortestPath((o)-[:MEMBER_OF|GENERIC_ALL|…*..12]->(t)) AS p
RETURN p
```

## Attack path enumeration

Canonical demo path (milliseconds, live-measured):

```cypher
MATCH (o {objectid: $oid}), (t {objectid: $target})
WITH shortestPath((o)-[:MEMBER_OF|GENERIC_ALL|…*..12]->(t)) AS p
RETURN p
```

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
OPTIONAL MATCH (s)-[r0:GENERIC_ALL]->(t)
WITH s, t, count(r0) AS pre
MERGE (s)-[r:GENERIC_ALL]->(t) SET r += $props RETURN pre
```

`RETURN pre` (the edge count BEFORE the merge) is the "newly created" signal:
`RETURN count(r)` after a MERGE is 1 whether the edge was created or already
existed, so it can never report an idempotent re-grant. `add_edge` returns
True exactly when `pre == 0` (and False when an endpoint is absent).

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
- the shipped container default query timeout is low — `GRAPH.CONFIG SET
  TIMEOUT_DEFAULT 0` is applied by the deployment; the client also passes
  explicit per-query timeouts
