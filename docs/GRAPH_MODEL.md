# SEVER — Graph Data Model

**TL;DR** — SEVER runs on **FalkorDB** (the load-bearing engine — remove it and the product
breaks, per the hackathon's rule 3). BloodHound CE / AzureHound collector JSON is parsed by a
deterministic two-pass ETL into **one graph per tenant** — `sever_demo`,
`sever_tenant001` .. `sever_tenantNNN` — native FalkorDB multi-tenancy. The model is 28 node
labels / 42 edge families on the loaded hybrid sample (ETL census below), and its core judgment is the **traversal set**:
only abusable relationship families chain into attack paths, structural edges never do.

## The model at a glance

```mermaid
erDiagram
  USER {
    string objectid
    string name
    bool owned
    bool unresolved
  }
  GROUP {
    string objectid
    string name
  }
  COMPUTER {
    string objectid
    bool isdc
  }
  DOMAIN {
    string objectid
    bool external
  }
  OU {
    string objectid
  }
  GPO {
    string objectid
  }
  CERTTEMPLATE {
    string objectid
  }
  ENTERPRISECA {
    string objectid
  }
  AZUSER {
    string objectid
    string name
    bool owned
  }
  AZSERVICEPRINCIPAL {
    string objectid
  }
  AZGROUP {
    string objectid
  }
  AZTENANT {
    string objectid
  }
  USER |o--o{ GROUP : "MEMBER_OF - membership, traversable"
  GROUP |o--o{ GROUP : "MEMBER_OF - nested groups"
  USER |o--o{ USER : "GENERIC_ALL and 24 more ACE-derived rights"
  USER |o--o{ COMPUTER : "ADMIN_TO - local admin"
  DOMAIN |o--o{ DOMAIN : "TRUSTED_BY - domain trusts, traversable"
  COMPUTER |o--|| OU : "CONTAINED_BY - structural, never traversed"
  OU |o--|| DOMAIN : "CONTAINED_BY - structural, never traversed"
  CERTTEMPLATE }o--|| ENTERPRISECA : "PUBLISHED_ON - structural, never traversed"
  USER |o--o| AZUSER : "SYNCED_TO - the hybrid bridge, 9 on the merged sample"
  AZUSER |o--o{ AZSERVICEPRINCIPAL : "AZOwns"
  AZUSER |o--o{ AZGROUP : "AZMemberOf"
  AZSERVICEPRINCIPAL |o--o{ AZGROUP : "AZAppRole"
  AZUSER |o--o{ AZTENANT : "AZMemberOf - tenant roles"
```

## The ETL pipeline

```mermaid
flowchart TD
  S["official SpecterOps sample zips - AD plus Entra, Apache-2.0"] --> U["unzip collector JSON - 31 files"]
  U --> P1["pass 1 - nodes: users, groups, computers, domains, OUs, GPOs, containers, CAs"]
  P1 --> P2["pass 2 - edges: memberships, ACE rights, delegation, trusts"]
  P2 --> Q{"principal referenced but never collected?"}
  Q -->|"yes"| UN["materialize an unresolved node - flagged honest, never invented"]
  Q -->|"no"| OK["keep the collected record"]
  UN --> H["deterministic 3x-identical edge hashes - prop variants stay distinct"]
  OK --> H
  H --> NB["node batches grouped by label - UNWIND $rows, MERGE on objectid"]
  H --> EB["edge batches grouped by rel type - props_key keeps variants distinct"]
  NB --> G["FalkorDB tenant graph"]
  EB --> G
  G --> IX["range index on objectid for each of the 15 indexed labels"]
```

Full derivation code: `sever/etl/ad_collectors.py` (two-pass parse,
unresolved-principal creation, deterministic). Measured on the official sample:
**31 collector files → 1,480 nodes / 12,450 edges, zero dangling references**
(`tests/test_etl.py`).

## Node label inventory (28 labels)

### On-prem AD surface (12 labels)

| Label | Source collector type | Key properties |
|---|---|---|
| `User` | users | objectid (SID), name, owned (bool), SPN flags |
| `Group` | groups | objectid (SID), name — **-512/-519 RIDs = crown jewels (Domain Admins / Enterprise Admins)** |
| `Computer` | computers | objectid, name, isdc |
| `Domain` | domains (+ external trust targets) | objectid, name, external |
| `OU` | ous | objectid, structural hierarchy |
| `GPO` | gpos | objectid, structural hierarchy |
| `Container` | containers | objectid, structural hierarchy |
| `CertTemplate` | certtemplates | objectid, ADCS surface (ESC derivation D2) |
| `EnterpriseCA` | CAs | objectid, ADCS surface |
| `RootCA` | CAs | objectid, ADCS surface |
| `AIACA` | CAs | objectid, ADCS surface |
| `NTAuthStore` | CAs | objectid, ADCS surface |

### Hybrid Entra surface (16 labels — the `_KIND_LABELS` set)

| Label | Role in the model |
|---|---|
| `AZUser` | cloud identity; **role holders are crown jewels** (name ends `-GlobalAdministrator`, case-insensitive) |
| `AZServicePrincipal` | service principal ownership chains (`AZOwns`, `AZAppRole`) |
| `AZApp` | application objects |
| `AZGroup` | cloud group membership (`AZMemberOf`) |
| `AZRole` | Entra roles |
| `AZDevice` | enrolled devices |
| `AZVM` | compute surface (`AZVMAdminLogin` and friends) |
| `AZVMScaleSet` | compute surface |
| `AZResourceGroup` | `AZRGUserAccessAdmin` |
| `AZSubscription` | `AZSubUserAccessAdmin` |
| `AZManagementGroup` | `AZMGUserAccessAdmin` |
| `AZKeyVault` | `AZKVUserAccessAdmin`, `AZKVContributor` |
| `AZLogicApp` | automation surface |
| `AZFunctionApp` | automation surface |
| `AZAutomationAccount` | automation surface |
| `AZTenant` | tenant root |

All AZ labels are keyed by the Entra object `id` instead of a SID — except
`AZTenant`, keyed by `tenantId`. The 16-label
`_KIND_LABELS` set is verified present in the loaded hybrid sample.

**Every node** carries: `objectid` (natural key, MERGE target), `owned`
(compromised flag), `unresolved` (true when the node was created for a
referenced-but-uncollected principal — surfaced honestly, BloodHound-faithful).

## Edge family inventory (42 families in the loaded hybrid sample)

ACE rights are derived from per-record `Aces[]` lists; memberships from `Members[]` /
`PrimaryGroupSID`; each maps 1:1 to a relationship type.

**ETL census on the official sample** (2026-10-18, `sever.etl.ad_collectors.parse_ad_dir`
+ `sever.etl.entra_collectors.merge_entra` — the same normalization the engine batch
queries load from; per-family edge counts in the sections below):

| Family group | Families | Edge count on the loaded sample |
|---|---|---|
| Membership & forest structure | 4 | 1,800 |
| ACE-derived rights | 22 | 10,635 |
| Delegation / local admin | 3 | 15 |
| Hybrid Entra edges + the bridge | 13 | 16,741 |
| **Total — loaded hybrid sample** | **42** | **29,191** (= 29 AD rel types + 12 Entra rel types + `SYNCED_TO`) |

### Membership & forest structure

| Relationship | From → To | Traversable? |
|---|---|---|
| `MEMBER_OF` | principal → group (nested groups included) | ✅ yes |
| `TRUSTED_BY` | domain → domain (incl. external trust targets, created as `external` Domain nodes) | ✅ yes |
| `CONTAINED_BY` | principal → OU/Domain | ❌ structural, never |
| `PUBLISHED_ON` | cert template → enterprise CA that publishes it | ❌ structural, never |

### ACE-derived rights (RightName → relationship type)

`GENERIC_ALL`, `GENERIC_WRITE`, `WRITE_DACL`, `WRITE_OWNER`, `OWNS`,
`FORCE_CHANGE_PASSWORD`, `ALL_EXTENDED_RIGHTS`, `WRITE_PROPERTY`, `RESET_PASSWORD`,
`GET_CHANGES`, `GET_CHANGES_IN_FILTERED_SET`, `GET_CHANGES_ALL`, `DCSYNC`,
`ADD_MEMBER`, `ADD_SELF`, `ADD_KEY_CREDENTIAL_LINK`, `ADD_ALLOWED_TO_ACT`,
`WRITE_ACCOUNT_RESTRICTIONS`, `READ_GMSAPASSWORD`, `READ_LAPSPASSWORD`, `MANAGE_CA`,
`MANAGE_CERTIFICATES`, `ENROLL`, `WRITE_PKIENROLLMENT_FLAG`, `WRITE_PKINAME_FLAG`.

**The sample emits exactly 22 of the 25** (ETL census, per-type edge counts):
`GENERIC_ALL` 3,314 · `GENERIC_WRITE` 580 · `WRITE_DACL` 2,228 · `WRITE_OWNER`
2,194 · `OWNS` 1,439 · `ALL_EXTENDED_RIGHTS` 188 · `ADD_KEY_CREDENTIAL_LINK` 180 ·
`ADD_MEMBER` 93 · `FORCE_CHANGE_PASSWORD` 52 · `ENROLL` 303 · `MANAGE_CA` 12 ·
`GET_CHANGES` 11 · `MANAGE_CERTIFICATES` 8 · `GET_CHANGES_ALL` 8 ·
`READ_GMSAPASSWORD` 7 · `GET_CHANGES_IN_FILTERED_SET` 6 ·
`WRITE_ACCOUNT_RESTRICTIONS` 5 · `WRITE_PKIENROLLMENT_FLAG` 2 ·
`WRITE_PKINAME_FLAG` 2 · `ADD_SELF` 1 · `ADD_ALLOWED_TO_ACT` 1 ·
`READ_LAPSPASSWORD` 1 — **`ENROLL` and the two `WRITE_PKI*` flag writes
included** (the sample's cert-template ACLs carry all three). The three absent
names — `WRITE_PROPERTY`, `RESET_PASSWORD`, `DCSYNC` — are handled by the model
but carry **zero edges on this sample**. The two `WRITE_PKI*` flag writes are
traversable (the owner-authorized PKI expansion added them to `TRAVERSAL_RELS`,
43 → 45); `ENROLL` stays deliberately non-traversable. Plus the derived
container-inherited control rights `GENERIC_RIGHT` and `EXTENDED_RIGHT`
(`sever/core/jewels.py`) — traversable, and likewise not emitted by this sample.

### Delegation / local admin

| Relationship | Meaning | Traversable? |
|---|---|---|
| `ALLOWED_TO_DELEGATE` | Kerberos delegation (1 edge on this sample) | ✅ yes |
| `ALLOWED_TO_ACT` | resource-based constrained delegation (1 edge) | ✅ yes |
| `ADMIN_TO` | local admin on a computer (13 edges) | ✅ yes |
| `HAS_SID_HISTORY` | SID-history pivot — ETL-derived from `HasSIDHistory`; zero edges on this sample | ✅ yes |
| `HAS_SPN_TARGET` | SPN target linkage — ETL-derived from `SPNTargets`; zero edges on this sample | ❌ never attacker-chainable |

### Hybrid Entra edges + the bridge

`AZOwns` (5,755), `AZMemberOf` (4,438), `AZAppRole` (3,725),
`AZRGUserAccessAdmin` (1,225), `AZVMAdminLogin` (332), `AZVMContributor` (528),
`AZVMUserAccessAdmin` (528), `AZVMAvereContributor` (68), `AZMGUserAccessAdmin` (49),
`AZKVUserAccessAdmin` (25), `AZKVContributor` (28), `AZSubUserAccessAdmin` (22) —
the exact 12-type Entra vocabulary (edge counts from the ETL census) — plus the
**hybrid bridge**: `SYNCED_TO` (18 directed edges = 9 bidirectional bridges), added
bidirectionally for every `AZUser` whose `onPremisesSecurityIdentifier` matches an
on-prem `User` (the pivot cloud → on-prem; measured: 9 bridges on the merged
14,422-node sample estate, `tests/test_entra.py`). Entra crown jewels are `AZUser`
role holders (name ends `-GlobalAdministrator`, matched case-insensitively — a
holder named `jdoe-GLOBALADMINISTRATOR` is still the jewel).

## The traversal set (the product's core judgment)

An attacker can chain only relationships in `sever/core/jewels.py::TRAVERSAL_RELS` —
the **45-type abusable subset** (memberships, ACL rights, delegation, GMSA/LAPS
password reads, trusts, the two PKI flag-write rights, the derived
container-inherited control rights, and the
hybrid Entra edges), upper-bounded at 12 hops. Structural edges
(`CONTAINED_BY`, `PUBLISHED_ON`) never count toward attack paths, and the emitted
`ENROLL` edges never chain either. This mirrors
BloodHound's abuse semantics for every right present in the sample.

| Family | Traversable | Never traversed |
|---|---|---|
| Memberships & trusts | `MEMBER_OF`, `TRUSTED_BY` | — |
| ACE-derived | the abusable rights above (incl. the two `WRITE_PKI*` flag writes) + `GENERIC_RIGHT`, `EXTENDED_RIGHT` | `ENROLL` |
| Delegation / local admin | `ALLOWED_TO_DELEGATE`, `ALLOWED_TO_ACT`, `ADMIN_TO`, `HAS_SID_HISTORY` | `HAS_SPN_TARGET` |
| Structural | — | `CONTAINED_BY`, `PUBLISHED_ON` |
| Hybrid | `SYNCED_TO` + the AZ edges | — |

The exact 45-type list, inlined as it runs, is in [`docs/CYPHER.md`](CYPHER.md).

## Metrics

- **Reachability** (headline): count of `owned` principals with any traversal-chain
  ≤ 12 hops to a crown jewel (`Group` with RID -512 Domain Admins / -519 Enterprise
  Admins; an owned principal that is itself a crown jewel counts as reached — the
  0-hop breach). The hop cap is live-verified inclusive: a 12-hop chain is
  reachable, a 13-hop chain is not.
- **Path frequency** (scoring input): per (owned → jewel) pair, one canonical
  shortest path is enumerated (ties off); each edge is scored by the number of
  these paths it lies on.
- **Interdiction**: cut the top-frequency edge → re-query reachability → before/after
  receipt with `GRAPH.PROFILE` timing. k=1 is the exact argmax of enumerated-path
  coverage — which is not the same as collapsing reachability (tied/alternative
  routes survive; the receipt says DEGRADED when they do). k>1 re-enumerates after
  each cut and picks the exact single-edge coverage argmax again: we say
  "greedy-ranked", never "optimal" and never "approximation bound" — the
  re-enumerating sequence optimizes pairs-disconnected (supermodular, no greedy
  guarantee; the classic (1−1/e) bound applies only to a frozen path set, which
  live receipts deliberately do not use). Optimal multi-edge interdiction is
  NP-hard: Israeli & Wood 2002; AAAI'22 arXiv:2112.13175.

## Multi-tenancy

`sever/synth/tenants.py` remaps identities injectively per tenant (SID subauthority
stride 10^15, uuid5 GUID namespaces) — tenants share zero objectids, structure and
crown-jewel counts are preserved, regeneration is deterministic
(`tests/test_synth.py`).
