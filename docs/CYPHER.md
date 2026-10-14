# SEVER — The Cypher Queries the Product Depends On

Rule 10 requires publishing the exact queries. These live as module constants in
`sever/core/falkor_port.py` and are reproduced here verbatim. `[:REL|…*1..12]`
is the abusable traversal pattern built from `sever/core/jewels.py::TRAVERSAL_RELS`.

## Crown jewels

```cypher
MATCH (g:Group)
WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
RETURN g.objectid AS objectid ORDER BY objectid
```

## Reachability (headline metric — "how many compromised principals can reach Domain Admins")

```cypher
MATCH (o {owned: true})
MATCH (o)-[:MEMBER_OF|GENERIC_ALL|GENERIC_WRITE|WRITE_DACL|WRITE_OWNER|OWNS|
  FORCE_CHANGE_PASSWORD|ALL_EXTENDED_RIGHTS|WRITE_PROPERTY|RESET_PASSWORD|
  GET_CHANGES|GET_CHANGES_IN_FILTERED_SET|GET_CHANGES_ALL|DCSYNC|HAS_SID_HISTORY|
  TRUSTED_BY|ALLOWED_TO_DELEGATE|ALLOWED_TO_ACT|ADMIN_TO|ADD_MEMBER|ADD_SELF|
  ADD_KEY_CREDENTIAL_LINK|ADD_ALLOWED_TO_ACT|WRITE_ACCOUNT_RESTRICTIONS|
  READ_GMSAPASSWORD|READ_LAPSPASSWORD|MANAGE_CA|MANAGE_CERTIFICATES|
  GENERIC_RIGHT|EXTENDED_RIGHT*1..12]->(t:Group)
WHERE t.objectid ENDS WITH '-512' OR t.objectid ENDS WITH '-519'
RETURN count(DISTINCT o) AS reachable
```

## Attack path (the visualization hop-chain)

```cypher
MATCH p = shortestPath((o {objectid: $oid})-[:…same traversal pattern…*1..12]->(t:Group {objectid: $target}))
RETURN p
```

## The interdiction (human-gated)

```cypher
-- pre-check (receipt: how many relationships will be removed)
MATCH (s {objectid: $src})-[r:GENERIC_ALL]->(t {objectid: $dst})
RETURN count(r) AS n

-- execution, only after explicit human approval
MATCH (s {objectid: $src})-[r:GENERIC_ALL]->(t {objectid: $dst})
DELETE r
```

Every receipt is re-queried live on camera; the PROFILE output of the re-query
(`GRAPH.PROFILE sever_demo "…"`) is shown with millisecond timing.

## Bulk ingestion (UNWIND batches — nodes then edges)

```cypher
UNWIND $rows AS r MERGE (n:User {objectid: r.objectid}) SET n += r.props
UNWIND $rows AS e MATCH (s {objectid: e.src}), (t {objectid: e.dst}) MERGE (s)-[:MEMBER_OF]->(t)
```

Edge property variants are keyed via `props_key` (canonical JSON) so inherited and
explicit ACEs coexist as distinct relationships.

## Live mutation (finding application)

```cypher
MATCH (s {objectid: $src}), (t {objectid: $dst})
MERGE (s)-[r:GENERIC_ALL]->(t) SET r += $props RETURN count(r)
```
