"""Synthetic multi-tenant generator — one FalkorDB graph per tenant org.

Per-tenant permutation of the base sample: domain SIDs, domain names, principal
names all remapped deterministically, so each tenant is a structurally identical
but data-distinct organization. Graph-per-tenant is FalkorDB's native
multi-tenancy: ``sever_tenant001`` .. ``sever_tenantNNN`` are isolated graphs in
ONE instance — the scale wall the demo runs on the 32GB build host.

Identity remapping is injective by construction:
- SIDs keep their RID tail (crown jewels -512/-519 stay detectable) while the
  authority-middle is shifted by tenant * 10^15 — larger than any real SID
  middle, so tenants can never overlap.
- GUIDs are remapped via uuid5 under a per-tenant namespace — distinct
  namespaces guarantee tenant-disjoint outputs for identical inputs.

Data provenance (rule 6): derived from the official SpecterOps Apache-2.0 sample
via deterministic transformation — synthetic, public, ours to ship.
"""
from __future__ import annotations

import re
import uuid

from sever.etl.ad_collectors import NormalizedGraph

_SID_TENANT_STRIDE = 10**15
# multi-subauthority SIDs: S-1-5-<first-sub>-<...>-<rid>; RID tail is PRESERVED
_SID_RE = re.compile(r"^(S-1-5-)(\d+)(-.+)$")
_GUID_RE = re.compile(r"^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")


def _remap_sid(oid: str, tenant_index: int) -> str:
    m = _SID_RE.match(oid)
    if not m:
        return oid
    head, first_sub, rest = m.groups()
    return f"{head}{int(first_sub) + tenant_index * _SID_TENANT_STRIDE}{rest}"


def _tenant_namespace(tenant_index: int) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_OID, f"sever-tenant-{tenant_index:03d}")


def _remap_guid(oid: str, tenant_index: int) -> str:
    if not _GUID_RE.match(oid or ""):
        return oid
    return str(uuid.uuid5(_tenant_namespace(tenant_index), oid)).upper()


def _tenant_suffix(i: int) -> str:
    return f"T{i:03d}"


def make_tenant(base: NormalizedGraph, tenant_index: int) -> NormalizedGraph:
    """Deterministic per-tenant copy of the base graph with remapped identities."""
    suf = _tenant_suffix(tenant_index)
    out = NormalizedGraph()
    id_map: dict[str, str] = {}

    for oid, node in base.nodes.items():
        if _SID_RE.match(oid):
            new_oid = _remap_sid(oid, tenant_index)
        elif _GUID_RE.match(oid or ""):
            new_oid = _remap_guid(oid, tenant_index)
        else:
            new_oid = f"{oid}~t{tenant_index:03d}"
        id_map[oid] = new_oid
        props = dict(node["props"])
        name = props.get("name")
        if isinstance(name, str) and name and "@" in name:
            props["name"] = name.rsplit("@", 1)[0] + f"@TENANT{suf}.CORP"
        elif isinstance(name, str) and name:
            props["name"] = f"{name}.{suf}"
        if "domain" in props and isinstance(props["domain"], str):
            props["domain"] = re.sub(r"^[A-Z]+\.", f"TENANT{suf}.", props["domain"])
        out.add_node(new_oid, node["label"], props)

    for edge in base.edges.values():
        src = id_map.get(edge["src"]) or edge["src"]
        dst = id_map.get(edge["dst"]) or edge["dst"]
        out.add_edge(src, dst, edge["rel"], dict(edge["props"]))

    out.stats = {
        "tenant": tenant_index,
        "node_count": len(out.nodes),
        "edge_count": len(out.edges),
    }
    return out


def tenant_graph_name(tenant_index: int) -> str:
    """FalkorDB graph key — one isolated graph per tenant org."""
    return f"sever_tenant{tenant_index:03d}"
