"""Shared interdiction semantics — traversal set and crown jewels.

The traversal relationship set is the load-bearing judgment of the whole
product: these are the relationships an attacker can chain. It mirrors
BloodHound's abuse semantics for the rights present in the CE sample data
and is documented explicitly in the README §5 (Graph data model) and
byte-for-byte in docs/CYPHER.md's inline list.
"""
from __future__ import annotations

# Relationships an attacker can actually chain (abuse semantics).
# Structural-only edges (CONTAINED_BY, PUBLISHED_ON) are deliberately excluded.
TRAVERSAL_RELS: tuple[str, ...] = (
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
    "ADD_MEMBER",
    "ADD_SELF",
    "ADD_KEY_CREDENTIAL_LINK",
    "ADD_ALLOWED_TO_ACT",
    "WRITE_ACCOUNT_RESTRICTIONS",
    "READ_GMSAPASSWORD",
    "READ_LAPSPASSWORD",
    "MANAGE_CA",
    "MANAGE_CERTIFICATES",
    # cert-template ACL flag writes (owner resolution #3): BloodHound CE
    # treats WritePKIEnrollmentFlag / WritePKINameFlag as abusable
    # (ESC-adjacent enrollment control); the sample emits 2+2 such edges,
    # which must be chainable, not invisible to path enumeration.
    "WRITE_PKIENROLLMENT_FLAG",
    "WRITE_PKINAME_FLAG",
    "GENERIC_RIGHT",          # container-inherited generic control
    "EXTENDED_RIGHT",
    # ---- hybrid Entra surface (only traversed when present) ----
    "SYNCED_TO",              # on-prem user -> synced Entra identity (the pivot)
    "AZOwns",
    "AZMemberOf",
    "AZAppRole",
    "AZVMAdminLogin",
    "AZVMContributor",
    "AZVMUserAccessAdmin",
    "AZVMAvereContributor",
    "AZRGUserAccessAdmin",
    "AZSubUserAccessAdmin",
    "AZMGUserAccessAdmin",
    "AZKVUserAccessAdmin",
    "AZKVContributor",
)

# closed set form (schema guard for live mutations; restores the constant the
# stub-sweep removed as "unused" before the audit tests that need it landed)
TRAVERSAL_RELS_SET: frozenset[str] = frozenset(TRAVERSAL_RELS)

DEFAULT_HOP_CAP = 12

# well-known RIDs: 512 = Domain Admins, 519 = Enterprise Admins
CROWN_JEWEL_RIDS: tuple[str, ...] = ("-512", "-519")

# Entra sample convention: role holders are NAMED after their role (the
# AzureHound sample models Global Admins as users like
# ``097ef6c2-GlobalAdministrator``). The name is collector data, so the
# suffix is matched case-insensitively — ``jdoe-GLOBALADMINISTRATOR`` is
# still the jewel, not an evasion.
GA_HOLDER_SUFFIX = "-GlobalAdministrator"


def is_crown_jewel(objectid: str, label: str = "Group", name: str = "") -> bool:
    """AD crown jewels: Domain Admins (-512) / Enterprise Admins (-519)
    groups — detected by SID, so a RENAMED group is still a jewel (and a decoy
    NAMED 'Domain Admins' with a different RID is not).
    Entra crown jewels: the sample's role-holder users (name ends
    -GlobalAdministrator, case-insensitive)."""
    if label == "Group":
        return objectid.endswith(CROWN_JEWEL_RIDS)
    if label == "AZUser":
        return name.lower().endswith(GA_HOLDER_SUFFIX.lower())
    return False


def cypher_traversal_pattern(hop_cap: int = DEFAULT_HOP_CAP) -> str:
    """Cypher relationship-type pattern for traversals (constants only — no user input).

    FalkorDB's shortestPath supports upper-bounded ranges only (*..N, no lower
    bound) — semantically identical for shortest-path reachability.
    """
    rels = "|".join(TRAVERSAL_RELS)
    return f"[:{rels}*..{hop_cap}]"
