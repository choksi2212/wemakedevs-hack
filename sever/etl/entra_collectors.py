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

# edge kinds: kind -> (rel, src_spec, dst_field)
# src_spec is either a list key ("owners", "members", "userAccessAdmins", ...)
# or a flat id field ("principalId"). Verified against the official AzureHound
# sample: Graph resources (users/groups/apps/SPs/devices) nest the full object
# under a singular key -> {"owner": {"id": ...}}; ARM resources (VMs,
# subscriptions, resource groups, management groups, key vaults) nest a
# roleAssignment -> {"userAccessAdmin": {"id": <roleAssignment ARM path>,
# "properties": {"principalId": <the actual principal>}}} — the principal is
# properties.principalId there, NOT the entry's own id.
_EDGE_KINDS: dict[str, tuple[str, str, str]] = {
    "AZServicePrincipalOwner": ("AZOwns", "owners", "servicePrincipalId"),
    "AZAppOwner": ("AZOwns", "owners", "appId"),  # appId remapped to app object id
    "AZGroupOwner": ("AZOwns", "owners", "groupId"),
    "AZDeviceOwner": ("AZOwns", "owners", "deviceId"),
    "AZVMOwner": ("AZOwns", "owners", "virtualMachineId"),
    "AZSubscriptionOwner": ("AZOwns", "owners", "subscriptionId"),
    "AZManagementGroupOwner": ("AZOwns", "owners", "managementGroupId"),
    "AZResourceGroupOwner": ("AZOwns", "owners", "resourceGroupId"),
    "AZKeyVaultOwner": ("AZOwns", "owners", "keyVaultId"),
    "AZGroupMember": ("AZMemberOf", "members", "groupId"),
    "AZAppRoleAssignment": ("AZAppRole", "principalId", "resourceId"),
    "AZVMAdminLogin": ("AZVMAdminLogin", "adminLogins", "virtualMachineId"),
    "AZVMContributor": ("AZVMContributor", "contributors", "virtualMachineId"),
    "AZVMUserAccessAdmin": ("AZVMUserAccessAdmin", "userAccessAdmins", "virtualMachineId"),
    "AZVMAvereContributor": ("AZVMAvereContributor", "avereContributors", "virtualMachineId"),
    "AZResourceGroupUserAccessAdmin": ("AZRGUserAccessAdmin", "userAccessAdmins", "resourceGroupId"),
    "AZSubscriptionUserAccessAdmin": ("AZSubUserAccessAdmin", "userAccessAdmins", "subscriptionId"),
    "AZManagementGroupUserAccessAdmin": ("AZMGUserAccessAdmin", "userAccessAdmins", "managementGroupId"),
    "AZKeyVaultUserAccessAdmin": ("AZKVUserAccessAdmin", "userAccessAdmins", "keyVaultId"),
    "AZKeyVaultContributor": ("AZKVContributor", "contributors", "keyVaultId"),
    "AZKeyVaultKVContributor": ("AZKVContributor", "kvContributors", "keyVaultId"),
}


def _principal_of(entry: Any, role_key: str) -> str:
    """Extract the principal object id from one owners/members/role entry.

    Two entry shapes occur in the official sample (both nested under a
    singular role key, with a flat-object fallback):
    - Graph object: {"owner": {"id": "<principal id>", ...}} (users, SPs, ...)
    - ARM roleAssignment: {"userAccessAdmin": {"id": "<roleAssignment path>",
      "properties": {"principalId": "<principal id>", ...}}}
    """
    inner = entry.get(role_key, entry) if isinstance(entry, dict) else {}
    if not isinstance(inner, dict):
        return ""
    props = inner.get("properties")
    if isinstance(props, dict) and props.get("principalId"):
        return str(props["principalId"])
    return str(inner.get("id") or "")


# @odata.type -> label, for materializing referenced-but-uncollected principals
_ODATA_LABELS: dict[str, str] = {
    "#microsoft.graph.user": "AZUser",
    "#microsoft.graph.group": "AZGroup",
    "#microsoft.graph.servicePrincipal": "AZServicePrincipal",
    "#microsoft.graph.device": "AZDevice",
}

# kind -> label of the dst resource, when the record references an
# uncollected resource (the kind itself is the type evidence)
_DST_LABELS: dict[str, str] = {
    "AZGroupOwner": "AZGroup",
    "AZGroupMember": "AZGroup",
    "AZAppOwner": "AZApp",
    "AZServicePrincipalOwner": "AZServicePrincipal",
    "AZDeviceOwner": "AZDevice",
    "AZVMOwner": "AZVM",
    "AZVMAdminLogin": "AZVM",
    "AZVMContributor": "AZVM",
    "AZVMUserAccessAdmin": "AZVM",
    "AZVMAvereContributor": "AZVM",
    "AZSubscriptionOwner": "AZSubscription",
    "AZSubscriptionUserAccessAdmin": "AZSubscription",
    "AZManagementGroupOwner": "AZManagementGroup",
    "AZManagementGroupUserAccessAdmin": "AZManagementGroup",
    "AZResourceGroupOwner": "AZResourceGroup",
    "AZResourceGroupUserAccessAdmin": "AZResourceGroup",
    "AZKeyVaultOwner": "AZKeyVault",
    "AZKeyVaultUserAccessAdmin": "AZKeyVault",
    "AZKeyVaultContributor": "AZKeyVault",
    "AZKeyVaultKVContributor": "AZKeyVault",
    "AZAppRoleAssignment": "AZServicePrincipal",  # resourceId is the resource app's SP
}


def _ensure_az_node(g: NormalizedGraph, objectid: str, label: str, props: dict[str, Any] | None = None) -> None:
    """Same honest-unresolved contract as the AD parser: materialize a node for
    a referenced-but-uncollected principal, never silently dropping the edge
    endpoint (and never inventing data the collectors did not give us)."""
    if objectid and objectid not in g.nodes:
        g.add_node(objectid, label, {"unresolved": True, **(props or {})})


def _ensure_src_from_entry(g: NormalizedGraph, entry: Any, role_key: str, src: str) -> None:
    """Graph-shaped entries inline the full referenced object — materialize it
    (label from @odata.type, name from displayName/UPN) when no record exists.
    ARM roleAssignment entries carry no principal type, so they are left alone."""
    if src in g.nodes or not isinstance(entry, dict):
        return
    inner = entry.get(role_key, entry)
    if not isinstance(inner, dict) or isinstance(inner.get("properties"), dict):
        return
    label = _ODATA_LABELS.get(str(inner.get("@odata.type") or ""))
    if not label:
        return
    name = inner.get("displayName") or inner.get("userPrincipalName") or ""
    _ensure_az_node(g, src, label, {"name": name} if name else None)


def parse_entra_file(path: str | Path) -> NormalizedGraph:
    """Parse an AzureHound JSON file (single {data:[...]} document)."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    g = NormalizedGraph()
    records = doc.get("data", [])

    # pre-pass: AzureHound references apps by appId (client id) in AZAppOwner
    # records while AZApp nodes are keyed by their OBJECT id — remap so owner
    # edges land on real nodes (verified: 6064/6064 owner appIds in the sample
    # are client ids, 0 match AZApp object ids).
    app_object_ids: dict[str, str] = {}
    for rec in records:
        if isinstance(rec, dict) and rec.get("kind") == "AZApp" and isinstance(rec.get("data"), dict):
            d = rec["data"]
            if d.get("appId") and d.get("id"):
                app_object_ids[str(d["appId"])] = str(d["id"])

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
            dst = str(data.get(dst_spec) or "")
            if kind == "AZAppOwner" and dst:
                dst = app_object_ids.get(dst, dst)
            if not dst:
                continue
            if dst not in g.nodes and kind in _DST_LABELS:
                _ensure_az_node(g, dst, _DST_LABELS[kind])
            entries = data.get(src_spec)
            if isinstance(entries, list):
                # list-shaped: one edge per owner/member/role-assignee entry
                role_key = src_spec[:-1] if src_spec.endswith("s") else src_spec
                for entry in entries:
                    src = _principal_of(entry, role_key)
                    if src:
                        _ensure_src_from_entry(g, entry, role_key, src)
                        g.add_edge(src, dst, rel, {"source_kind": kind})
            else:
                src = str(entries or "")
                if src:
                    # flat kinds (e.g. AZAppRoleAssignment) carry principalType
                    if src not in g.nodes:
                        pt = _ODATA_LABELS.get(
                            f"#microsoft.graph.{str(data.get('principalType') or '').lower()}", ""
                        )
                        if pt:
                            _ensure_az_node(g, src, pt)
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
