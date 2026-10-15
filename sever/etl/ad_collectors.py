"""Parse BloodHound CE collector JSON dumps into a normalized graph model.

Input: directory of `<timestamp>_<type>.json` files (SharpHound CE v6 format),
each ``{"data": [...], "meta": {"type": "...", "version": N}}``.

Output: ``NormalizedGraph`` — nodes and edges ready for Cypher batch emission
or direct in-memory graph construction. Every edge endpoint is guaranteed to
resolve (external trust targets get unresolved Domain nodes).

Deliberately NOT derived (verified against the CE sample, all 34 computer
records): ``Sessions``/``PrivilegedSessions``/``RegistrySessions`` (presence
data — a session is exposure, not a grant; the engine's TRAVERSAL_RELS models
privilege edges only, so HasSession/CanRDP edges would be dead weight), and
``UserRights``/``Status``/``DCRegistryData``/``GPO Links`` (display/metadata
the traversal set does not consume). These fields are accepted on records
without effect — the hostile-input tests pin that they never crash the
parser or leak into node props.

Hostile-input contract: structurally corrupt files fail LOUD (FileNotFoundError
for an empty dir, JSONDecodeError for bad JSON, ValueError with the file name
for a non-object document or non-list ``data``). Wrong-typed or malformed
record fields are counted in ``stats["skipped"]`` and skipped — parse cleanly
and visibly, never crash silently, never emit a garbage edge.
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


# relationship types whose semantics we surface explicitly in queries.
# Verified against the BloodHound CE sample: every ACE RightName in the data
# (22 distinct rights) maps mechanically through _right_to_rel onto a
# relationship type; the abusable ones are all attacker-chainable in
# sever.core.jewels.TRAVERSAL_RELS. ENROLL is emitted but deliberately
# non-traversable (BloodHound CE marks the Enroll edge non-traversable too).
# ESC1/ESC2/AUTO_ENROLL were removed: nothing derives or queries them — BH CE
# synthesizes ADCSESC1/2 edges from template properties, which this ETL does
# not implement.
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
        "GET_CHANGES_IN_FILTERED_SET",
        "GET_CHANGES_ALL",
        "DCSYNC",
        "HAS_SID_HISTORY",
        "TRUSTED_BY",
        "ALLOWED_TO_DELEGATE",
        "ALLOWED_TO_ACT",
        "ADMIN_TO",
        "ENROLL",
        "ADD_MEMBER",
        "ADD_SELF",
        "ADD_KEY_CREDENTIAL_LINK",
        "ADD_ALLOWED_TO_ACT",
        "WRITE_ACCOUNT_RESTRICTIONS",
        "READ_GMSAPASSWORD",
        "READ_LAPSPASSWORD",
        "MANAGE_CA",
        "MANAGE_CERTIFICATES",
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
        """Add an edge, deduped on (src, dst, rel, canonical props).

        Self-loops (src == dst) are dropped on purpose: a self-ACL (e.g.
        ENTERPRISE ADMINS holds WriteDacl on itself — 32 such group self-ACEs
        in the CE sample) can never change reachability of any other node, and
        FalkorDB paths cannot traverse a self-loop usefully. Dropping is also
        the hostile-input defense: a record referencing its own SID never
        yields a garbage edge.

        Prop values are coerced to FalkorDB-safe primitives (bool/int/float/str;
        dict/list become canonical JSON strings) — FalkorDB rejects
        non-primitive map values, so a hostile collector file must fail at
        parse time, not at load time.
        """
        if not src or not dst or src == dst:
            return False
        clean = {}
        for k, v in (props or {}).items():
            if v is None or v == "":
                continue
            clean[k] = _prim(v)
        key = (src, dst, rel, json.dumps(clean, sort_keys=True, default=str))
        if key not in self.edges:
            self.edges[key] = {"src": src, "dst": dst, "rel": rel, "props": clean}
            return True
        return False


def _prim(v: Any) -> Any:
    """Coerce one prop value to a FalkorDB-safe primitive."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, default=str)
    return str(v)


def _clean_props(raw: Any) -> dict[str, Any]:
    """Flatten a collector ``Properties`` dict into primitive-typed props.

    Non-dict input (a hostile or corrupt file: string, list, ...) yields {}
    rather than a crash — the record is still counted by the caller.
    """
    if not isinstance(raw, dict):
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


def _list_field(rec: dict[str, Any], key: str, skipped: dict[str, int], counter: str) -> list:
    """Fetch ``rec[key]`` as a list, counting truthy non-list values.

    A hostile or corrupt collector file may put a string (or dict, int, ...)
    where a list belongs. Iterating a bare string would walk it CHARACTER BY
    CHARACTER — for HasSIDHistory that emitted one garbage HAS_SID_HISTORY
    edge per character. Wrong-typed fields are counted and treated as empty:
    parse cleanly and visibly, never crash, never emit garbage.
    """
    val = rec.get(key)
    if val is None:
        return []
    if not isinstance(val, list):
        skipped[counter] = skipped.get(counter, 0) + 1
        return []
    return val


def _ref_sid(entry: Any, skipped: dict[str, int], counter: str) -> str:
    """ObjectIdentifier of a {ObjectIdentifier, ObjectType} ref entry; only
    string SIDs are accepted (str() of a dict would invent a garbage id)."""
    if not isinstance(entry, dict):
        skipped[counter] = skipped.get(counter, 0) + 1
        return ""
    sid = entry.get("ObjectIdentifier")
    if not isinstance(sid, str) or not sid:
        skipped[counter] = skipped.get(counter, 0) + 1
        return ""
    return sid


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
        # fail loud on structurally-corrupt documents — never half-ingest
        if not isinstance(doc, dict):
            raise ValueError(
                f"collector file {f.name}: top level must be a JSON object, got {type(doc).__name__}"
            )
        data = doc.get("data", [])
        if data is None:
            data = []
        if not isinstance(data, list):
            raise ValueError(
                f"collector file {f.name}: 'data' must be a list, got {type(data).__name__}"
            )
        docs.append((label, data))
        for rec in data:
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


def _parse_record(g: NormalizedGraph, rec: Any, label: str, skipped: dict[str, int], edges: bool = True) -> None:
    # ---- record-level guard: a non-dict record is counted, never a crash ----
    if not isinstance(rec, dict):
        skipped["malformed_record"] = skipped.get("malformed_record", 0) + 1
        return
    oid = str(rec.get("ObjectIdentifier") or "")
    if not oid:
        skipped["no_objectid"] = skipped.get("no_objectid", 0) + 1
        return
    props = rec.get("Properties")
    if props is not None and not isinstance(props, dict):
        skipped["malformed_properties"] = skipped.get("malformed_properties", 0) + 1
        props = None
    props = _clean_props(props)
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
    # Every ACE on the record becomes principal --RIGHT--> record. The
    # IsInherited flag propagates verbatim onto the edge (`inherited` prop),
    # so inherited vs direct ACEs stay distinguishable in the graph.
    for ace in _list_field(rec, "Aces", skipped, "malformed_aces"):
        if not isinstance(ace, dict):
            skipped["ace_malformed_entry"] = skipped.get("ace_malformed_entry", 0) + 1
            continue
        principal = ace.get("PrincipalSID")
        right = ace.get("RightName")
        if not principal or not right:
            skipped["ace_missing_fields"] = skipped.get("ace_missing_fields", 0) + 1
            continue
        # str() of a dict/int principal or right would invent a garbage id/rel
        if not isinstance(principal, str) or not isinstance(right, str):
            skipped["ace_malformed_fields"] = skipped.get("ace_malformed_fields", 0) + 1
            continue
        _ensure_node(g, principal, str(ace.get("PrincipalType") or ""))
        g.add_edge(principal, oid, _right_to_rel(right), {"inherited": bool(ace.get("IsInherited", False))})

    # ---- membership edges ----
    for member in _list_field(rec, "Members", skipped, "malformed_members"):
        member_sid = _ref_sid(member, skipped, "member_malformed_entry")
        if not member_sid:
            continue
        _ensure_node(g, member_sid, str((member or {}).get("ObjectType") or ""))
        g.add_edge(member_sid, oid, "MEMBER_OF")
    pg = rec.get("PrimaryGroupSID")
    if pg is not None:
        if not isinstance(pg, str) or not pg:
            skipped["malformed_primarygroupsid"] = skipped.get("malformed_primarygroupsid", 0) + 1
        else:
            _ensure_node(g, pg, "Group")
            g.add_edge(oid, pg, "MEMBER_OF", {"primary": True})

    # ---- container/OU hierarchy ----
    cb = rec.get("ContainedBy")
    if cb is not None and not isinstance(cb, dict):
        skipped["malformed_containedby"] = skipped.get("malformed_containedby", 0) + 1
    elif isinstance(cb, dict):
        parent = cb.get("ObjectIdentifier")
        if not isinstance(parent, str) or not parent:
            skipped["malformed_containedby"] = skipped.get("malformed_containedby", 0) + 1
        else:
            _ensure_node(g, parent, "Container")
            g.add_edge(oid, parent, "CONTAINED_BY")

    # ---- user-specific ----
    for sid in _list_field(rec, "HasSIDHistory", skipped, "malformed_hassidhistory"):
        if not isinstance(sid, str) or not sid:
            skipped["sidhistory_malformed_entry"] = skipped.get("sidhistory_malformed_entry", 0) + 1
            continue
        _ensure_node(g, sid, "User")
        g.add_edge(oid, sid, "HAS_SID_HISTORY")
    for tgt in _list_field(rec, "SPNTargets", skipped, "malformed_spntargets"):
        if not isinstance(tgt, dict):
            skipped["spntarget_malformed_entry"] = skipped.get("spntarget_malformed_entry", 0) + 1
            continue
        endpoint = tgt.get("EndpointAddress")
        if not isinstance(endpoint, str) or not endpoint:
            skipped["spntarget_malformed_entry"] = skipped.get("spntarget_malformed_entry", 0) + 1
            continue
        _ensure_node(g, endpoint, "Computer")  # keep the zero-dangling invariant
        g.add_edge(oid, endpoint, "HAS_SPN_TARGET", {"service": tgt.get("Service")})

    # ---- delegation / RBCD (users & computers) ----
    # msDS-AllowedToDelegateTo lists the TARGETS the record's principal may
    # delegate to, so the edge runs record -> target — BloodHound CE: the edge
    # "points from the principal that holds the privilege to the target it can
    # delegate to" (sample: KRB-DEL-01 -> DC01, never the reverse).
    for ref in _list_field(rec, "AllowedToDelegate", skipped, "malformed_allowedtodelegate"):
        sid = _ref_sid(ref, skipped, "delegate_malformed_entry")
        if not sid:
            continue
        _ensure_node(g, sid, str((ref or {}).get("ObjectType") or "Computer"))
        g.add_edge(oid, sid, "ALLOWED_TO_DELEGATE")
    # msDS-AllowedToActOnBehalfOfOtherIdentity lives ON the target computer:
    # the refs are the principals allowed to act on rec, so the edge runs
    # ref -> record (BloodHound CE: "from the principal that can act to the
    # computer that trusts it"). Sample: EXTCA02 -> EXTCA01.
    for ref in _list_field(rec, "AllowedToAct", skipped, "malformed_allowedtoact"):
        sid = _ref_sid(ref, skipped, "act_malformed_entry")
        if not sid:
            continue
        _ensure_node(g, sid, str((ref or {}).get("ObjectType") or "Computer"))
        g.add_edge(sid, oid, "ALLOWED_TO_ACT")

    # ---- computer local groups -> local admin ----
    # SharpHound CE v6 carries local-group members under "Results" (verified
    # against the CE sample: entries are {ObjectIdentifier, ObjectType} refs;
    # the "Members" key does not exist in this format).
    # BloodHound CE derives AdminTo ONLY from the local ADMINISTRATORS group
    # (local-group RID -544); the sample also lists Users (-545)/Guests (-546)/
    # RemoteDesktopUsers (-555)/Account Operators (-548)... whose members are
    # NOT local admins — e.g. RID -513 (Domain Users) sits in local "Users".
    # Non-admin groups produce no edge, faithful to BH.
    for lg in _list_field(rec, "LocalGroups", skipped, "malformed_localgroups"):
        if not isinstance(lg, dict):
            skipped["localgroup_malformed_entry"] = skipped.get("localgroup_malformed_entry", 0) + 1
            continue
        lg_oid = lg.get("ObjectIdentifier")
        if not isinstance(lg_oid, str) or not lg_oid:
            skipped["localgroup_malformed_entry"] = skipped.get("localgroup_malformed_entry", 0) + 1
            continue
        if lg_oid.rsplit("-", 1)[-1] != "544":
            continue
        results = lg.get("Results")
        if results is None:
            results = lg.get("Members")
        if results is None:
            continue
        if not isinstance(results, list):
            skipped["localgroup_malformed_results"] = skipped.get("localgroup_malformed_results", 0) + 1
            continue
        for member in results:
            sid = _ref_sid(member, skipped, "localgroup_malformed_member")
            if not sid:
                continue
            _ensure_node(g, sid, str((member or {}).get("ObjectType") or "User"))
            g.add_edge(sid, oid, "ADMIN_TO", {"group": lg.get("Name"), "local_group_id": lg_oid})

    # ---- domain trusts ----
    # One TRUSTED_BY edge per trust, record domain -> TargetDomainSid,
    # direction kept as a prop — exactly what BloodHound CE models (it does
    # NOT reverse or drop the edge for Inbound trusts; direction is data).
    # Uncollected target domains materialize as Domain nodes flagged external
    # (sample: REVENANT.CORP, CHILD.WRAITH.CORP).
    for trust in _list_field(rec, "Trusts", skipped, "malformed_trusts"):
        if not isinstance(trust, dict):
            skipped["trust_malformed_entry"] = skipped.get("trust_malformed_entry", 0) + 1
            continue
        target_sid = trust.get("TargetDomainSid")
        if not isinstance(target_sid, str) or not target_sid:
            skipped["trust_missing_target_sid"] = skipped.get("trust_missing_target_sid", 0) + 1
            continue
        target_name = trust.get("TargetDomainName")
        if target_name is not None and not isinstance(target_name, str):
            target_name = json.dumps(target_name, default=str)
        if target_sid not in g.nodes:
            g.add_node(target_sid, "Domain", {"name": target_name, "external": True})
        g.add_edge(
            oid,
            target_sid,
            "TRUSTED_BY",
            {"direction": trust.get("TrustDirection"), "trusttype": trust.get("TrustType")},
        )

    # ---- enterprise CA publishes templates ----
    for tpl in _list_field(rec, "EnabledCertTemplates", skipped, "malformed_enabledcerttemplates"):
        tpl_sid = _ref_sid(tpl, skipped, "certtemplate_malformed_entry")
        if not tpl_sid:
            continue
        _ensure_node(g, tpl_sid, "CertTemplate")
        g.add_edge(tpl_sid, oid, "PUBLISHED_ON")
