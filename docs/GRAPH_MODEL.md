# SEVER — Graph Data Model

SEVER runs on **FalkorDB** (the load-bearing engine — remove it and the product breaks, per the
hackathon's rule 3). Identity graphs are ingested from BloodHound CE collector JSON
(official SpecterOps sample data, Apache-2.0) into one **graph per tenant** —
`sever_demo`, `sever_tenant001` .. `sever_tenantNNN` — native FalkorDB multi-tenancy.

## Node labels

| Label | Source collector type | Key properties |
|---|---|---|
| `User` | users | objectid (SID), name, owned (bool), SPN flags |
| `Group` | groups | objectid (SID), name — **-512/-512 RIDs = crown jewels** |
| `Computer` | computers | objectid, name, isdc |
| `Domain` | domains (+ external trust targets) | objectid, name, external |
| `OU`, `GPO`, `Container` | ous / gpos / containers | structural hierarchy |
| `CertTemplate`, `EnterpriseCA`, `RootCA`, `AIACA`, `NTAuthStore` | certtemplates / CAs | ADCS surface (ESC derivation D2) |

Every node: `objectid` (natural key, MERGE target), `owned` (compromised flag),
`placeholder` (true when referenced-but-uncollected — BloodHound-faithful).

## Relationship types (edges)

ACE rights are derived from per-record `Aces[]` lists; memberships from `Members[]` /
`PrimaryGroupSID`; each maps 1:1 to a relationship type:

- Membership: `MEMBER_OF`
- ACL abuse (RightName → type): `GENERIC_ALL`, `GENERIC_WRITE`, `WRITE_DACL`, `WRITE_OWNER`,
  `OWNS`, `FORCE_CHANGE_PASSWORD`, `ALL_EXTENDED_RIGHTS`, `WRITE_PROPERTY`, `RESET_PASSWORD`,
  `GET_CHANGES`, `GET_CHANGES_IN_FILTERED_SET`, `GET_CHANGES_ALL`, `DCSYNC`, `ADD_MEMBER`,
  `ADD_SELF`, `ADD_KEY_CREDENTIAL_LINK`, `ADD_ALLOWED_TO_ACT`, `WRITE_ACCOUNT_RESTRICTIONS`,
  `READ_GMSAPASSWORD`, `READ_LAPSPASSWORD`, `MANAGE_CA`, `MANAGE_CERTIFICATES`, `ENROLL`, …
- Delegation/session: `ALLOWED_TO_DELEGATE`, `ALLOWED_TO_ACT`, `ADMIN_TO`, `HAS_SID_HISTORY`,
  `HAS_SPN_TARGET`
- Forest structure: `TRUSTED_BY` (domain trusts, incl. external placeholders), `CONTAINED_BY`,
  `PUBLISHED_ON` (CA → cert template)

Full derivation code: `sever/etl/ad_collectors.py` (two-pass parse, placeholder creation,
deterministic). Measured on the official sample: **31 collector files → 1,480 nodes /
12,437 edges, zero dangling references** (`tests/test_etl.py`).

## Hybrid Entra overlay (AzureHound side)

Hybrid estates merge the AzureHound collector output (`sever/etl/entra_collectors.py`),
adding the cloud identity surface — `AZUser`, `AZServicePrincipal`, `AZApp`, `AZGroup`,
`AZRole`, `AZDevice`, `AZVM`, `AZResourceGroup`, `AZSubscription`, `AZManagementGroup`,
`AZKeyVault`, `AZTenant`, … (keyed by Entra object `id` instead of SID). Edges:
`AZOwns`, `AZMemberOf`, `AZAppRole`, `AZVMAdminLogin`, `AZVMContributor`,
`AZVMUserAccessAdmin`, `AZVMAvereContributor`, `AZRGUserAccessAdmin`, `AZSubUserAccessAdmin`,
`AZMGUserAccessAdmin`, `AZKVUserAccessAdmin`, `AZKVContributor`, … plus the **hybrid
bridge**: `SYNCED_TO`, added bidirectionally for every `AZUser` whose
`onPremisesSecurityIdentifier` matches an on-prem `User` (the pivot cloud → on-prem;
measured: 9 bridges on the merged 14,402-node sample estate,
`tests/test_entra.py`). Entra crown jewels are `AZUser` role holders
(name ends `-GlobalAdministrator`).

## The traversal set (the product's core judgment)

An attacker can chain only relationships in `sever/core/jewels.py::TRAVERSAL_RELS` —
the abusable subset (memberships, ACL rights, delegation, sessions, trusts).
Structural edges (`CONTAINED_BY`, `PUBLISHED_ON`) never count toward attack paths.
This mirrors BloodHound's abuse semantics for every right present in the sample.

## Metrics

- **Reachability** (headline): count of `owned` principals with any traversal-chain
  ≤ 12 hops to a crown jewel (`Group` with RID -512 Domain Admins / -519 Enterprise Admins).
- **Path frequency** (scoring input): per (owned → jewel) shortest path enumeration;
  each edge scored by the number of paths it lies on.
- **Interdiction**: cut the top-frequency edge → re-query reachability → before/after
  receipt with `GRAPH.PROFILE` timing. k=1 exact for the enumerated-candidate restriction;
  k>1 greedy path-coverage with the (1−1/e) submodular guarantee — we say
  "greedy-ranked", never "optimal" (optimal multi-edge interdiction is NP-hard:
  Israeli & Wood 2002; AAAI'22 arXiv:2112.13175).

## Multi-tenancy

`sever/synth/tenants.py` remaps identities injectively per tenant (SID subauthority
stride 10^15, uuid5 GUID namespaces) — tenants share zero objectids, structure and
crown-jewel counts are preserved, regeneration is deterministic
(`tests/test_synth.py`).
