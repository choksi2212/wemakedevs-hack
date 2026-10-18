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
from typing import Any

from sever.etl.ad_collectors import NormalizedGraph

# kind -> (label, id_field)
_KIND_LABELS: dict[str, tuple[str, str]] = {
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
_FLAT_SRC_FIELD = "principalId"  # the only flat (string) src field: AZAppRoleAssignment

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

    Only string/int ids are accepted — str() of a dict would invent a garbage
    principal id (hostile-input guard).
    """
    inner = entry.get(role_key, entry) if isinstance(entry, dict) else {}
    if not isinstance(inner, dict):
        return ""
    props = inner.get("properties")
    if isinstance(props, dict):
        pid = props.get("principalId")
        if isinstance(pid, bool) or not isinstance(pid, (str, int)) or pid == "":
            return ""
        return str(pid)
    val = inner.get("id")
    if isinstance(val, bool) or not isinstance(val, (str, int)) or val == "":
        return ""
    return str(val)


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
    if not isinstance(name, str):
        name = json.dumps(name, default=str)  # never a non-primitive prop value
    _ensure_az_node(g, src, label, {"name": name} if name else None)


def _as_str_id(val: Any) -> str:
    """String ids only — str() of a dict/int here would invent a garbage key."""
    if isinstance(val, bool) or not isinstance(val, (str, int)) or val == "":
        return ""
    return str(val)


def parse_entra_file(path: str | Path) -> NormalizedGraph:
    """Parse an AzureHound JSON file (single {data:[...]} document).

    Hostile-input contract mirrors the AD parser: corrupt documents fail
    LOUD (ValueError with a clear message); wrong-typed records/fields are
    counted in ``stats["skipped"]`` and skipped — never a crash, never a
    garbage edge. Record kinds the model does not consume stay visible in
    ``stats["kind_counts"]`` (they are data, not errors).
    """
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(
            f"entra collector file {Path(path).name}: top level must be a JSON object, got {type(doc).__name__}"
        )
    records = doc.get("data", [])
    if records is None:
        records = []
    if not isinstance(records, list):
        raise ValueError(
            f"entra collector file {Path(path).name}: 'data' must be a list, got {type(records).__name__}"
        )
    g = NormalizedGraph()
    skipped: dict[str, int] = {}

    # pre-pass: AzureHound references apps by appId (client id) in AZAppOwner
    # records while AZApp nodes are keyed by their OBJECT id — remap so owner
    # edges land on real nodes (verified: 6064/6064 owner appIds in the sample
    # are client ids, 0 match AZApp object ids).
    app_object_ids: dict[str, str] = {}
    for rec in records:
        if isinstance(rec, dict) and rec.get("kind") == "AZApp" and isinstance(rec.get("data"), dict):
            d = rec["data"]
            app_id, obj_id = _as_str_id(d.get("appId")), _as_str_id(d.get("id"))
            if app_id and obj_id:
                app_object_ids[app_id] = obj_id

    for rec in records:
        if not isinstance(rec, dict):
            skipped["malformed_record"] = skipped.get("malformed_record", 0) + 1
            continue
        kind = rec.get("kind", "")
        if not isinstance(kind, str):
            skipped["malformed_kind"] = skipped.get("malformed_kind", 0) + 1
            continue
        data = rec.get("data")
        if data is None:
            data = {}
        if not isinstance(data, dict):
            skipped[f"malformed_data:{kind}"] = skipped.get(f"malformed_data:{kind}", 0) + 1
            continue

        if kind in _KIND_LABELS:
            label, id_field = _KIND_LABELS[kind]
            oid = _as_str_id(data.get(id_field))
            if not oid:
                skipped[f"missing_id:{kind}"] = skipped.get(f"missing_id:{kind}", 0) + 1
                continue
            # primitive-typed props only (FalkorDB rejects non-primitive maps)
            raw_name = data.get("displayName") or data.get("userPrincipalName")
            raw_upn = data.get("userPrincipalName")
            raw_sid = data.get("onPremisesSecurityIdentifier")
            raw_appid = data.get("appId")
            raw_desc = data.get("description")
            props = {
                k: v for k, v in {
                    "name": raw_name if isinstance(raw_name, str) else (json.dumps(raw_name, default=str) if raw_name else None),
                    "upn": raw_upn if isinstance(raw_upn, str) else (json.dumps(raw_upn, default=str) if raw_upn else None),
                    "enabled": data.get("accountEnabled") if isinstance(data.get("accountEnabled"), (bool, int, float, str)) else None,
                    "onprem_sid": raw_sid if isinstance(raw_sid, str) else (json.dumps(raw_sid, default=str) if raw_sid else None),
                    # description is the one prop we deliberately cap (200 chars)
                    "description": (raw_desc if isinstance(raw_desc, str) else json.dumps(raw_desc, default=str))[:200] if raw_desc is not None else None,
                    "appid": raw_appid if isinstance(raw_appid, str) else (json.dumps(raw_appid, default=str) if raw_appid else None),
                }.items() if v not in (None, "", [])
            }
            props.setdefault("owned", False)
            g.add_node(oid, label, props)

        elif kind in _EDGE_KINDS:
            rel, src_spec, dst_spec = _EDGE_KINDS[kind]
            dst = _as_str_id(data.get(dst_spec))
            if kind == "AZAppOwner" and dst:
                dst = app_object_ids.get(dst, dst)
            if not dst:
                skipped[f"edge_missing_dst:{kind}"] = skipped.get(f"edge_missing_dst:{kind}", 0) + 1
                continue
            if dst not in g.nodes and kind in _DST_LABELS:
                _ensure_az_node(g, dst, _DST_LABELS[kind])
            entries = data.get(src_spec)
            if isinstance(entries, list):
                # list-shaped: one edge per owner/member/role-assignee entry
                role_key = src_spec[:-1] if src_spec.endswith("s") else src_spec
                for entry in entries:
                    src = _principal_of(entry, role_key)
                    if not src:
                        skipped[f"edge_malformed_src:{kind}"] = skipped.get(f"edge_malformed_src:{kind}", 0) + 1
                        continue
                    _ensure_src_from_entry(g, entry, role_key, src)
                    # ARM roleAssignment entries (properties.principalId) carry
                    # NO type information, and Graph entries without
                    # @odata.type carry none either — the zero-dangling
                    # invariant wins: materialize an honest typeless
                    # AZPrincipal placeholder rather than a dangling edge
                    # (on the full sample these principals always exist via
                    # other records, so this only fires on sparse/hostile data)
                    if src not in g.nodes:
                        _ensure_az_node(g, src, "AZPrincipal")
                    g.add_edge(src, dst, rel, {"source_kind": kind})
            elif src_spec == _FLAT_SRC_FIELD:
                # flat kinds (e.g. AZAppRoleAssignment) carry principalId as a
                # plain string — anything else (dict/list/None) is malformed
                src = _as_str_id(entries)
                if not src:
                    skipped[f"edge_missing_src:{kind}"] = skipped.get(f"edge_missing_src:{kind}", 0) + 1
                    continue
                if src not in g.nodes:
                    pt = _ODATA_LABELS.get(
                        f"#microsoft.graph.{str(data.get('principalType') or '').lower()}", ""
                    )
                    # zero-dangling invariant: an unknown/absent principalType
                    # still yields an honest typeless placeholder, never a
                    # dangling edge (sparse-data hole found by audit3 tests)
                    _ensure_az_node(g, src, pt or "AZPrincipal")
                g.add_edge(src, dst, rel, {"source_kind": kind})
            else:
                # list-shaped kind with a non-list value: str() would emit a
                # garbage edge — count it instead. NULL (or an absent key) is
                # NOT that case: it is the ordinary "no owners/members
                # recorded" encoding (9,673 records in the official sample
                # carry owners/members: null) — empty and uncounted, exactly
                # like the AD parser's _list_field treats the same shape
                # (audit M66: these were miscounted as edge_malformed_src).
                if entries is not None:
                    skipped[f"edge_malformed_src:{kind}"] = skipped.get(f"edge_malformed_src:{kind}", 0) + 1

    g.stats = {
        "records": len(records),
        "node_count": len(g.nodes),
        "edge_count": len(g.edges),
        "kind_counts": {},
        "skipped": skipped,
    }
    for rec in records:
        k = rec.get("kind", "?") if isinstance(rec, dict) and isinstance(rec.get("kind"), str) else "<malformed>"
        g.stats["kind_counts"][k] = g.stats["kind_counts"].get(k, 0) + 1
    return g


def merge_entra(ad: NormalizedGraph, entra: NormalizedGraph, bidirectional: bool = True) -> NormalizedGraph:
    """Merge an Entra graph into the AD graph, adding SYNCED_TO bridge edges
    for every AZUser carrying an on-prem SID that matches an AD User.

    Non-mutating: ``ad`` and ``entra`` are left untouched and a new merged
    graph is returned. Bidirectional by default — password-synced identities
    are ONE identity: control flows on-prem->cloud AND cloud->on-prem (the
    MGM/Storm-0558 lesson).
    """
    merged = NormalizedGraph()
    merged.nodes = {
        oid: {"objectid": oid, "label": n["label"], "props": dict(n.get("props", {}))}
        for oid, n in ad.nodes.items()
    }
    merged.edges = {
        key: {**e, "props": dict(e.get("props", {}))}
        for key, e in ad.edges.items()
    }
    merged.stats = dict(ad.stats)

    for oid, node in entra.nodes.items():
        if oid in merged.nodes:
            # collision: merge props, but an ``unresolved`` flag must never
            # leak onto a principal the other side resolved (audit L69: an
            # entra placeholder colliding with a resolved AD principal used
            # to flag that principal unresolved). The RESOLVED record wins
            # in both directions: strip the placeholder's flag before
            # merging, and drop a stale AD-side flag when the entra record
            # is itself resolved.
            props = dict(node.get("props", {}))
            entra_unresolved = props.pop("unresolved", None)
            merged.add_node(oid, node["label"], props)
            if entra_unresolved is None:
                merged.nodes[oid]["props"].pop("unresolved", None)
        else:
            merged.nodes[oid] = {"objectid": oid, "label": node["label"], "props": dict(node["props"])}
    for edge in entra.edges.values():
        merged.add_edge(edge["src"], edge["dst"], edge["rel"], dict(edge["props"]))

    ad_user_ids = {n for n, nd in merged.nodes.items() if nd.get("label") == "User"}
    bridged = 0
    for oid, node in entra.nodes.items():
        if node.get("label") != "AZUser":
            continue
        sid = node.get("props", {}).get("onprem_sid")
        if sid and sid in ad_user_ids:
            merged.add_edge(sid, oid, "SYNCED_TO", {"hybrid": True})
            if bidirectional:
                merged.add_edge(oid, sid, "SYNCED_TO", {"hybrid": True, "direction": "reverse"})
            bridged += 1

    # honest stats: recompute the merged graph's OWN label/rel censuses (the
    # pre-merge AD stats are stale after the overlay) and carry the Entra
    # parser's skip ledger forward under its own key.
    merged.stats["entra_bridges"] = bridged
    merged.stats["node_count"] = len(merged.nodes)
    merged.stats["edge_count"] = len(merged.edges)
    label_counts: dict[str, int] = {}
    for node in merged.nodes.values():
        label_counts[node["label"]] = label_counts.get(node["label"], 0) + 1
    merged.stats["label_counts"] = label_counts
    rel_counts: dict[str, int] = {}
    for edge in merged.edges.values():
        rel_counts[edge["rel"]] = rel_counts.get(edge["rel"], 0) + 1
    merged.stats["rel_counts"] = rel_counts
    merged.stats["entra_skipped"] = dict(entra.stats.get("skipped", {}))
    return merged
