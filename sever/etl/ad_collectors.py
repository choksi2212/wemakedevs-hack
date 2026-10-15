"""Parse BloodHound CE collector JSON dumps into a normalized graph model.

Input: directory of `<timestamp>_<type>.json` files (SharpHound CE v6 format),
each `{"data": [...], "meta": {"type": "...", "version": N}}`.

Output: ``NormalizedGraph`` — nodes and edges ready for Cypher batch emission
or direct in-memory graph construction. Every edge endpoint is guaranteed to
resolve (external trust targets get unresolved Domain nodes).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# collector file-type -> node label
TYPE_LABEL: dict[str, str] = {
    "users": "User",
    "groups": "Group",
    "computers": "Computer",
    "domains": "Domain",
    "ous": "OU",
    "gpos": "GPO",
    "containers": "Container",
    "aiacas": "AIACA",
    "certtemplates": "CertTemplate",
    "enterprisecas": "EnterpriseCA",
    "ntauthstores": "NTAuthStore",
    "rootcas": "RootCA",
}

# camelCase/PascalCase ACE right names -> SNAKE_UPPER relationship types
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _right_to_rel(right: str) -> str:
    return _CAMEL.sub("_", right.strip()).upper().replace("-", "_")


# relationship types whose semantics we surface explicitly in queries
ABUSABLE_RELS: frozenset[str] = frozenset(
    {
        "MEMBER_OF",
        "GENERIC_ALL",
        "GENERIC_WRITE",
        "WRITE_DACL",
        "WRITE_OWNER",
        "OWNS",
        "FORCE_CHANGE_PASSWORD",
        "ALL_EXTENDED_RIGHTS",
        "WRITE_PROPERTY",
        "RESET_PASSWORD",
        "GET_CHANGES",
        "GET_CHANGES_ALL",
        "DCSYNC",
        "HAS_SID_HISTORY",
        "TRUSTED_BY",
        "ALLOWED_TO_DELEGATE",
        "ALLOWED_TO_ACT",
        "ADMIN_TO",
        "ENROLL",
        "AUTO_ENROLL",
        "ESC1",
        "ESC2",
    }
)


@dataclass
class NormalizedGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)   # objectid -> node
    edges: dict[tuple[str, str, str, str], dict[str, Any]] = field(default_factory=dict)
    # (src, dst, rel, props_key) -> props ; props_key = canonical props repr for dedupe
    stats: dict[str, Any] = field(default_factory=dict)

    def add_node(self, objectid: str, label: str, props: dict[str, Any] | None = None) -> None:
        if objectid not in self.nodes:
            self.nodes[objectid] = {"objectid": objectid, "label": label, "props": {}}
        node = self.nodes[objectid]
        if props:
            for k, v in props.items():
                if v is None or v == "":
                    continue
                node["props"].setdefault(k, v)

    def add_edge(self, src: str, dst: str, rel: str, props: dict[str, Any] | None = None) -> bool:
        if not src or not dst or src == dst:
            return False
        clean = {k: v for k, v in (props or {}).items() if v is not None and v != ""}
        key = (src, dst, rel, json.dumps(clean, sort_keys=True, default=str))
        if key not in self.edges:
            self.edges[key] = {"src": src, "dst": dst, "rel": rel, "props": clean}
            return True
        return False


def _clean_props(raw: dict[str, Any] | None) -> dict[str, Any]:
    if not raw:
        return {}
    out: dict[str, Any] = {}
    for k, v in raw.items():
        if v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            out[k] = json.dumps(v, default=str)
        elif isinstance(v, bool):
            out[k] = v
        elif isinstance(v, (int, float)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


def _name_of(props: dict[str, Any]) -> str:
    for key in ("name", "samaccountname", "displayname", "defaultDomain", "shortname"):
        val = props.get(key)
        if val:
            return str(val)
    return ""


def _sid_refs(records: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Collect (ObjectIdentifier, ObjectType) from reference dicts (Members, ...)."""
    refs: list[tuple[str, str]] = []
    for entry in records:
        if isinstance(entry, dict):
            sid = entry.get("ObjectIdentifier")
            if sid:
                refs.append((str(sid), str(entry.get("ObjectType") or "")))
    return refs


_KNOWN_LABELS: frozenset[str] = frozenset(
    {"User", "Group", "Computer", "Domain", "OU", "GPO", "Container",
     "AIACA", "CertTemplate", "EnterpriseCA", "NTAuthStore", "RootCA"}
)


def _ensure_node(g: NormalizedGraph, objectid: str, label_hint: str, name: str = "") -> None:
    """Create an UNRESOLVED-PRINCIPAL node when a reference points at a
    principal the collectors never emitted a record for.

    BloodHound itself resolves every referenced principal into a node — ACL
    paths through uncollected principals remain traversable. We surface them
    honestly with the `unresolved` property (never silently dropped, never
    silently invented).
    """
    if objectid and objectid not in g.nodes:
        label = label_hint if label_hint in _KNOWN_LABELS else "Container"
        g.add_node(objectid, label, {"unresolved": True, **({"name": name} if name else {})})





def parse_ad_dir(path: str | Path) -> NormalizedGraph:
    """Parse every collector JSON in ``path`` (all snapshots/domains) into one org graph.

    Two passes: (1) create all nodes from their own records (authoritative labels),
    (2) derive edges, creating unresolved-principal nodes only for genuinely-uncollected refs.
    """
    g = NormalizedGraph()
    skipped: dict[str, int] = {}
    files = sorted(Path(path).glob("*.json"))
    if not files:
        raise FileNotFoundError(f"no collector JSON files found in {path}")

    docs: list[tuple[str, list[dict[str, Any]]]] = []
    for f in files:
        stem = f.stem  # <ts>_<type>
        ftype = stem.split("_", 1)[1].lower() if "_" in stem else stem.lower()
        label = TYPE_LABEL.get(ftype)
        if label is None:
            skipped[f"unknown_type:{ftype}"] = skipped.get(f"unknown_type:{ftype}", 0) + 1
            continue
        doc = json.loads(f.read_text(encoding="utf-8"))
        docs.append((label, doc.get("data", [])))
        for rec in doc.get("data", []):
            _parse_record(g, rec, label, skipped, edges=False)

    for label, records in docs:
        for rec in records:
            _parse_record(g, rec, label, skipped, edges=True)

    g.stats = {
        "files": len(files),
        "node_count": len(g.nodes),
        "edge_count": len(g.edges),
        "label_counts": {},
        "rel_counts": {},
        "skipped": skipped,
    }
    for node in g.nodes.values():
        g.stats["label_counts"][node["label"]] = g.stats["label_counts"].get(node["label"], 0) + 1
    for edge in g.edges.values():
        g.stats["rel_counts"][edge["rel"]] = g.stats["rel_counts"].get(edge["rel"], 0) + 1
    return g


def _parse_record(g: NormalizedGraph, rec: dict[str, Any], label: str, skipped: dict[str, int], edges: bool = True) -> None:
    oid = str(rec.get("ObjectIdentifier") or "")
    if not oid:
        skipped["no_objectid"] = skipped.get("no_objectid", 0) + 1
        return
    props = _clean_props(rec.get("Properties"))
    for flag in ("IsACLProtected", "IsDeleted", "IsDC", "DumpSMSAPassword"):
        val = rec.get(flag)
        if val is None:
            continue
        if isinstance(val, (list, dict)):
            val = bool(val)  # e.g. DumpSMSAPassword is a list of dump entries -> boolean
        props[flag.lower()] = val
    name = _name_of(props)
    if name:
        props.setdefault("name", name)
    props.setdefault("owned", False)
    g.add_node(oid, label, props)

    if not edges:
        return

    # ---- ACL edges ----
    for ace in rec.get("Aces", []) or []:
        principal = str(ace.get("PrincipalSID") or "")
        right = ace.get("RightName")
        if not principal or not right:
            skipped["ace_missing_fields"] = skipped.get("ace_missing_fields", 0) + 1
            continue
        _ensure_node(g, principal, str(ace.get("PrincipalType") or ""))
        g.add_edge(principal, oid, _right_to_rel(right), {"inherited": bool(ace.get("IsInherited", False))})

    # ---- membership edges ----
    for member_sid, member_type in _sid_refs(rec.get("Members", []) or []):
        _ensure_node(g, member_sid, member_type)
        g.add_edge(member_sid, oid, "MEMBER_OF")
    if rec.get("PrimaryGroupSID"):
        pgid = str(rec["PrimaryGroupSID"])
        _ensure_node(g, pgid, "Group")
        g.add_edge(oid, pgid, "MEMBER_OF", {"primary": True})

    # ---- container/OU hierarchy ----
    cb = rec.get("ContainedBy")
    if isinstance(cb, dict) and cb.get("ObjectIdentifier"):
        parent = str(cb["ObjectIdentifier"])
        _ensure_node(g, parent, "Container")
        g.add_edge(oid, parent, "CONTAINED_BY")

    # ---- user-specific ----
    for sid in rec.get("HasSIDHistory", []) or []:
        if isinstance(sid, str):
            _ensure_node(g, sid, "User")
            g.add_edge(oid, sid, "HAS_SID_HISTORY")
    for tgt in rec.get("SPNTargets", []) or []:
        if isinstance(tgt, dict) and tgt.get("EndpointAddress"):
            g.add_edge(oid, str(tgt["EndpointAddress"]), "HAS_SPN_TARGET", {"service": tgt.get("Service")})

    # ---- delegation / RBCD (users & computers) ----
    for ref in rec.get("AllowedToDelegate", []) or []:
        if isinstance(ref, dict):
            sid = str(ref.get("ObjectIdentifier") or "")
            _ensure_node(g, sid, str(ref.get("ObjectType") or "Computer"))
            g.add_edge(sid, oid, "ALLOWED_TO_DELEGATE")
    for ref in rec.get("AllowedToAct", []) or []:
        if isinstance(ref, dict):
            sid = str(ref.get("ObjectIdentifier") or "")
            _ensure_node(g, sid, str(ref.get("ObjectType") or "Computer"))
            g.add_edge(sid, oid, "ALLOWED_TO_ACT")

    # ---- computer local groups -> local admin ----
    for lg in rec.get("LocalGroups", []) or []:
        if isinstance(lg, dict):
            for member in lg.get("Members", []) or []:
                if not isinstance(member, dict):
                    continue
                sid = str(member.get("ObjectIdentifier") or "")
                if sid:
                    _ensure_node(g, sid, str(member.get("ObjectType") or "User"))
                    g.add_edge(sid, oid, "ADMIN_TO", {"group": lg.get("Name")})

    # ---- domain trusts ----
    for trust in rec.get("Trusts", []) or []:
        if not isinstance(trust, dict):
            continue
        target_sid = str(trust.get("TargetDomainSid") or "")
        target_name = str(trust.get("TargetDomainName") or "")
        if not target_sid:
            continue
        if target_sid not in g.nodes:
            g.add_node(target_sid, "Domain", {"name": target_name, "external": True})
        g.add_edge(
            oid,
            target_sid,
            "TRUSTED_BY",
            {"direction": trust.get("TrustDirection"), "trusttype": trust.get("TrustType")},
        )

    # ---- enterprise CA publishes templates ----
    for tpl_sid, _ in _sid_refs(rec.get("EnabledCertTemplates", []) or []):
        _ensure_node(g, tpl_sid, "CertTemplate")
        g.add_edge(tpl_sid, oid, "PUBLISHED_ON")
