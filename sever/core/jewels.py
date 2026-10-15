"""Shared interdiction semantics — traversal set and crown jewels.

The traversal relationship set is the load-bearing judgment of the whole
product: these are the relationships an attacker can chain. It mirrors
BloodHound's abuse semantics for the rights present in the CE sample data
and is documented explicitly in the README (rule 10).
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

DEFAULT_HOP_CAP = 12

# well-known RIDs: 512 = Domain Admins, 519 = Enterprise Admins
CROWN_JEWEL_RIDS: tuple[str, ...] = ("-512", "-519")


def is_crown_jewel(objectid: str, label: str = "Group", name: str = "") -> bool:
    """AD crown jewels: Domain Admins (-512) / Enterprise Admins (-519) groups.
    Entra crown jewels: the sample's role-holder users (name ends -GlobalAdministrator)."""
    if label == "Group":
        return objectid.endswith(CROWN_JEWEL_RIDS)
    if label == "AZUser":
        return name.endswith("-GlobalAdministrator")
    return False


def cypher_traversal_pattern(hop_cap: int = DEFAULT_HOP_CAP) -> str:
    """Cypher relationship-type pattern for traversals (constants only — no user input).

    FalkorDB's shortestPath supports upper-bounded ranges only (*..N, no lower
    bound) — semantically identical for shortest-path reachability.
    """
    rels = "|".join(TRAVERSAL_RELS)
    return f"[:{rels}*..{hop_cap}]"
