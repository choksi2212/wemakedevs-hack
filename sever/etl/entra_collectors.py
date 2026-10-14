"""Parse AzureHound (Entra) collector JSON into the same NormalizedGraph shape.

The official SpecterOps example file models role holders as users NAMED after
their role (e.g. ``097ef6c2-GlobalAdministrator``) — in this dataset, reaching
that user IS reaching Global Administrator. SEVER treats such AZUser nodes as
Entra crown jewels (see sever/core/jewels.py).

Hybrid bridge: AZUser records carrying ``onPremisesSecurityIdentifier`` get a
``SYNCED_TO`` edge from the matching on-prem AD User (same SID) — the classic
on-prem-to-cloud pivot (MGM / Storm-0558 canon).
"""
from __future__ import annotations

import json
from pathlib import Path

from sever.etl.ad_collectors import NormalizedGraph

GA_HOLDER_SUFFIX = "-GlobalAdministrator"

# kind -> (label, id_field)
_KIND_LABELS: dict[str, str] = {
    "AZUser": ("AZUser", "id"),
    "AZServicePrincipal": ("AZServicePrincipal", "id"),
    "AZApp": ("AZApp", "id"),
    "AZGroup": ("AZGroup", "id"),
    "AZRole": ("AZRole", "id"),
    "AZDevice": ("AZDevice", "id"),
    "AZVM": ("AZVM", "id"),
    "AZVMScaleSet": ("AZVMScaleSet", "id"),
    "AZResourceGroup": ("AZResourceGroup", "id"),
    "AZSubscription": ("AZSubscription", "id"),
    "AZManagementGroup": ("AZManagementGroup", "id"),
    "AZKeyVault": ("AZKeyVault", "id"),
    "AZLogicApp": ("AZLogicApp", "id"),
    "AZFunctionApp": ("AZFunctionApp", "id"),
    "AZAutomationAccount": ("AZAutomationAccount", "id"),
    "AZTenant": ("AZTenant", "tenantId"),
}

# edge kinds: kind -> (rel, src_from, dst_from)
# src/dst extractor specs: 'owner' (nested owner.id), 'member' (nested member.id),
# 'principal' (principalId), 'resource' (resourceId), etc.
_EDGE_KINDS: dict[str, tuple[str, str, str]] = {
    "AZServicePrincipalOwner": ("AZOwns", "owner", "servicePrincipalId"),
    "AZAppOwner": ("AZOwns", "owner", "appId"),
    "AZGroupOwner": ("AZOwns", "owner", "groupId"),
    "AZDeviceOwner": ("AZOwns", "owner", "deviceId"),
    "AZSubscriptionOwner": ("AZOwns", "owner", "subscriptionId"),
    "AZManagementGroupOwner": ("AZOwns", "owner", "managementGroupId"),
    "AZResourceGroupOwner": ("AZOwns", "owner", "resourceGroupId"),
    "AZKeyVaultOwner": ("AZOwns", "owner", "keyVaultId"),
    "AZGroupMember": ("AZMemberOf", "member", "groupId"),
    "AZAppRoleAssignment": ("AZAppRole", "principalId", "resourceId"),
    "AZVMOwner": ("AZOwns", "owner", "vmId"),
    "AZVMAdminLogin": ("AZVMAdminLogin", "principalId", "vmId"),
    "AZVMContributor": ("AZVMContributor", "principalId", "vmId"),
    "AZVMUserAccessAdmin": ("AZVMUserAccessAdmin", "principalId", "vmId"),
    "AZVMAvereContributor": ("AZVMAvereContributor", "principalId", "vmId"),
    "AZResourceGroupUserAccessAdmin": ("AZRGUserAccessAdmin", "principalId", "resourceGroupId"),
    "AZSubscriptionUserAccessAdmin": ("AZSubUserAccessAdmin", "principalId", "subscriptionId"),
    "AZManagementGroupUserAccessAdmin": ("AZMGUserAccessAdmin", "principalId", "managementGroupId"),
    "AZKeyVaultUserAccessAdmin": ("AZKVUserAccessAdmin", "principalId", "keyVaultId"),
    "AZKeyVaultContributor": ("AZKVContributor", "principalId", "keyVaultId"),
    "AZKeyVaultKVContributor": ("AZKVContributor", "principalId", "keyVaultId"),
}


def _endpoint(data: dict, spec: str) -> str:
    """Extract an object id from an edge record per the extractor spec."""
    if spec in ("owner", "member"):
        nested = data.get(f"{spec}s") or []
        first = nested[0] if nested else {}
        inner = first.get(spec, first) if isinstance(first, dict) else {}
        return str(inner.get("id") or first.get("id") or "") if isinstance(first, dict) else ""
    return str(data.get(spec) or "")


def parse_entra_file(path: str | Path) -> NormalizedGraph:
    """Parse an AzureHound JSON file (single {data:[...]} document)."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    g = NormalizedGraph()
    records = doc.get("data", [])

    for rec in records:
        kind = rec.get("kind", "")
        data = rec.get("data", {}) or {}

        if kind in _KIND_LABELS:
            label, id_field = _KIND_LABELS[kind]
            oid = str(data.get(id_field) or "")
            if not oid:
                continue
            props = {
                k: v for k, v in {
                    "name": data.get("displayName") or data.get("userPrincipalName"),
                    "upn": data.get("userPrincipalName"),
                    "enabled": data.get("accountEnabled"),
                    "onprem_sid": data.get("onPremisesSecurityIdentifier"),
                    "description": (data.get("description") or "")[:200],
                    "appid": data.get("appId"),
                }.items() if v not in (None, "", [])
            }
            props.setdefault("owned", False)
            g.add_node(oid, label, props)

        elif kind in _EDGE_KINDS:
            rel, src_spec, dst_spec = _EDGE_KINDS[kind]
            if src_spec in ("owner", "member"):
                # list-shaped: one edge per owner/member entry
                for entry in data.get(f"{src_spec}s") or []:
                    inner = entry.get(src_spec, entry) if isinstance(entry, dict) else {}
                    src = str(inner.get("id") or "") if isinstance(inner, dict) else ""
                    dst = str(data.get(dst_spec) or "")
                    if src and dst:
                        g.add_edge(src, dst, rel, {"source_kind": kind})
            else:
                src = str(data.get(src_spec) or "")
                dst = str(data.get(dst_spec) or "")
                if src and dst:
                    g.add_edge(src, dst, rel, {"source_kind": kind})

    g.stats = {
        "records": len(records),
        "node_count": len(g.nodes),
        "edge_count": len(g.edges),
        "kind_counts": {},
    }
    for rec in records:
        k = rec.get("kind", "?")
        g.stats["kind_counts"][k] = g.stats["kind_counts"].get(k, 0) + 1
    return g


def merge_entra(ad: NormalizedGraph, entra: NormalizedGraph, bidirectional: bool = True) -> NormalizedGraph:
    """Merge an Entra graph into the AD graph, adding SYNCED_TO bridge edges
    for every AZUser carrying an on-prem SID that matches an AD User.

    Bidirectional by default — password-synced identities are ONE identity:
    control flows on-prem->cloud AND cloud->on-prem (the MGM/Storm-0558 lesson).
    """
    for oid, node in entra.nodes.items():
        if oid in ad.nodes:
            ad.add_node(oid, node["label"], node["props"])  # merge props
        else:
            ad.nodes[oid] = {"objectid": oid, "label": node["label"], "props": dict(node["props"])}
    for edge in entra.edges.values():
        ad.add_edge(edge["src"], edge["dst"], edge["rel"], dict(edge["props"]))

    ad_user_ids = {n for n, nd in ad.nodes.items() if nd.get("label") == "User"}
    bridged = 0
    for oid, node in entra.nodes.items():
        if node.get("label") != "AZUser":
            continue
        sid = node.get("props", {}).get("onprem_sid")
        if sid and sid in ad_user_ids:
            ad.add_edge(sid, oid, "SYNCED_TO", {"hybrid": True})
            if bidirectional:
                ad.add_edge(oid, sid, "SYNCED_TO", {"hybrid": True, "direction": "reverse"})
            bridged += 1

    ad.stats = dict(ad.stats)
    ad.stats["entra_bridges"] = bridged
    ad.stats["node_count"] = len(ad.nodes)
    ad.stats["edge_count"] = len(ad.edges)
    return ad
