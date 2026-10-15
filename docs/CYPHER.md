# SEVER — The Cypher Queries the Product Depends On

Rule 10 requires publishing the exact queries. These are the **live-verified**
forms — executed against falkordb 6.0.0 (case-log receipts in
`docs/receipts/receipts_live_sever_demo.json`; GRAPH.PROFILE receipt of the canonical
path query in `docs/receipts/profile.txt`, ~1.1 ms in-engine on the
1,480-node / 12,450-edge demo tenant) — maintained as module constants in
`sever/core/falkor_port.py` (`JEWELS_QUERY`, `AZ_JEWELS_QUERY`,
`MARK_OWNED_QUERY`, `OWNED_QUERY`, `REACHABILITY_METHOD`,
`PATH_QUERY_TEMPLATE`, `CANONICAL_PATH_QUERY_TEMPLATE`,
`CUT_COUNT_QUERY_TEMPLATE`, `CUT_DELETE_QUERY_TEMPLATE`, `ADD_EDGE_QUERY`,
`INDEXED_LABELS`) and `sever/core/jewels.py` (`TRAVERSAL_RELS`,
`cypher_traversal_pattern`).

`[:REL|…]` is the abusable traversal pattern emitted by
`cypher_traversal_pattern(12)`: the **43 relationship types** of
`TRAVERSAL_RELS` (the attacker-chainable subset of the data model —
structural-only edges like `CONTAINED_BY`/`PUBLISHED_ON` are deliberately
excluded; hybrid Entra edges appear only in hybrid estates), upper-bounded
`*..12`. FalkorDB's `shortestPath` rejects lower bounds (`*1..N` throws), so
the pattern is emitted as `*..N`.

## Crown jewels

```cypher
MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
RETURN g.objectid AS objectid ORDER BY objectid
// Entra jewels (hybrid estates):
MATCH (u:AZUser) WHERE u.name ENDS WITH '-GlobalAdministrator'
RETURN u.objectid AS objectid ORDER BY objectid
```

## Ownership (who the attacker already controls)

```cypher
// F-001, the credential breach — mark a principal owned:
MATCH (n {objectid: $oid}) SET n.owned = true
// read the owned set back (reachability iterates exactly these):
MATCH (n {owned: true}) RETURN n.objectid AS objectid
```

## Reachability (headline metric)

Count of owned principals with ≥1 shortest path to any crown jewel.
`REACHABILITY_METHOD` is per-pair existence: the port runs
`PATH_QUERY_TEMPLATE` for every (owned, jewel) pair (60 s per-query timeout)
and counts the principal as soon as any path comes back:

```cypher
MATCH (o {objectid: $oid}), (t {objectid: $target})
CALL algo.SPpaths({sourceNode: o, targetNode: t, pathCount: 100}) YIELD path
RETURN path
```

No `relTypes` is passed to the procedure, so it walks **every** relationship
type — reachability means "connected by anything at all". The
abusable-relationship restriction lives in the pattern of the canonical form
below.

## Attack path enumeration

Canonical demo path — `CANONICAL_PATH_QUERY_TEMPLATE` with the full
43-type pattern inlined so it runs verbatim (milliseconds, live-measured):

```cypher
MATCH (o {objectid: $oid}), (t {objectid: $target}) WITH shortestPath((o)-[:MEMBER_OF|GENERIC_ALL|GENERIC_WRITE|WRITE_DACL|WRITE_OWNER|OWNS|FORCE_CHANGE_PASSWORD|ALL_EXTENDED_RIGHTS|WRITE_PROPERTY|RESET_PASSWORD|GET_CHANGES|GET_CHANGES_IN_FILTERED_SET|GET_CHANGES_ALL|DCSYNC|HAS_SID_HISTORY|TRUSTED_BY|ALLOWED_TO_DELEGATE|ALLOWED_TO_ACT|ADMIN_TO|ADD_MEMBER|ADD_SELF|ADD_KEY_CREDENTIAL_LINK|ADD_ALLOWED_TO_ACT|WRITE_ACCOUNT_RESTRICTIONS|READ_GMSAPASSWORD|READ_LAPSPASSWORD|MANAGE_CA|MANAGE_CERTIFICATES|GENERIC_RIGHT|EXTENDED_RIGHT|SYNCED_TO|AZOwns|AZMemberOf|AZAppRole|AZVMAdminLogin|AZVMContributor|AZVMUserAccessAdmin|AZVMAvereContributor|AZRGUserAccessAdmin|AZSubUserAccessAdmin|AZMGUserAccessAdmin|AZKVUserAccessAdmin|AZKVContributor*..12]->(t)) AS p RETURN p
```

Offline analysis mode (`paths_to_jewels(ties=True)`) enumerates tied shortest
paths via the built-in procedure — the same `PATH_QUERY_TEMPLATE` as
reachability (measured: cross-domain tie sets take 15–25s+ per pair — the
live agent loop uses the canonical form):

```cypher
MATCH (o {objectid: $oid}), (t {objectid: $target})
CALL algo.SPpaths({sourceNode: o, targetNode: t, pathCount: 100}) YIELD path
RETURN path
```

## The interdiction (human-gated)

`{rel}` is the only interpolated slot in these templates. It is validated
against `^[A-Z][A-Z0-9_]{0,63}$` (`_valid_rel` in `falkor_port.py`) **before**
it can reach the query string — the Cypher injection guard; relationship
types are a closed vocabulary from the data model.

```cypher
// pre-check receipt: how many relationships will be removed
MATCH (s {objectid: $src})-[r:GENERIC_ALL]->(t {objectid: $dst})
RETURN count(r) AS n
// execution — only after explicit human approval
MATCH (s {objectid: $src})-[r:GENERIC_ALL]->(t {objectid: $dst})
DELETE r
```

## Live mutation (finding application — F-003 grants an ACE mid-demo)

Same injection guard on `{rel}`:

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

## Bulk ingestion (UNWIND batches — nodes then edges, 1000 rows per batch)

Emitted by `sever/etl/cypher_batches.py` — nodes grouped by label, then
edges grouped by relationship type:


```cypher
// nodes:
UNWIND $rows AS r MERGE (n:User {objectid: r.objectid}) SET n += r.props
// edges carrying properties (props_key = JSON of the props, so prop-variants
// of the same relationship stay distinct edges):
UNWIND $rows AS e MATCH (s {objectid: e.src}), (t {objectid: e.dst})
MERGE (s)-[r:MEMBER_OF {props_key: e.props_key}]->(t) SET r += e.props
// edges with no properties:
UNWIND $rows AS e MATCH (s {objectid: e.src}), (t {objectid: e.dst})
MERGE (s)-[:MEMBER_OF]->(t)
```

## Range indexes (objectid lookups)

At the end of `load()`, a range index on the natural key is created for each
of the 15 `INDEXED_LABELS` (User, Group, Computer, Domain, OU, GPO, Container,
CertTemplate, EnterpriseCA, RootCA, AIACA, NTAuthStore, AZUser,
AZServicePrincipal, AZApp) — idempotent, an already-indexed label is skipped:

```cypher
CREATE INDEX FOR (n:User) ON (n.objectid)
```

## Engine quirks mapped during the build (all live-verified)

- `shortestPath` is only valid as a WITH/RETURN expression, not `MATCH p = …`
- `shortestPath` hop ranges must be upper-bounded (`*..N`; a lower bound such
  as `*1..N` is rejected) — hence `cypher_traversal_pattern` emits `*..N`
- `algo.SPpaths` is configured with node references, not patterns — the call
  in `PATH_QUERY_TEMPLATE` passes only `sourceNode`/`targetNode`/`pathCount`
  (no `relTypes`, so every relationship type is walked) and its returned
  paths carry raw integer node ids on edges, so hops are rebuilt from the
  ordered node list via index-zip (`_row_to_hops`)
- property values must be primitives or primitive arrays — FalkorDB rejects
  maps/lists, so ingest JSON-serializes list/dict property values
  (`_clean_props`), and the boolean-shaped collector flags (`IsACLProtected`,
  `IsDeleted`, `IsDC`, `DumpSMSAPassword`), which arrive list-shaped in the
  sample data, are coerced to booleans
- falkordb 6.0.0 ships `TIMEOUT_DEFAULT = 0` (no server-side kill) and
  `docker-compose.yml` carries `FALKORDB_ARGS=TIMEOUT_DEFAULT 0` only as an
  optional, commented-out knob — the client never relies on a server default
  anyway: every traversal read passes an explicit per-query timeout (60 s per
  reachability pair and scalar reads, 30 s per path enumeration)
