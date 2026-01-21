from typing import Dict, List, Set
from fastapi import HTTPException

# Map Entra group object IDs -> role name
# Put your real group GUIDs here (from Entra)
GROUP_TO_ROLE: Dict[str, str] = {
    # "GUID_VIEWER": "viewer",
    # "GUID_ANALYST": "analyst",
    # "GUID_ADMIN": "admin",
}

ROLE_PERMS: Dict[str, Set[str]] = {
    # For demo purposes, viewer has all permissions (no groups configured yet)
    # In production: uncomment the GROUP_TO_ROLE mappings and use these permissions:
    "viewer": {"tickets:read", "tickets:create", "tickets:comment", "admin:export_audit"},  # Demo: full access
    "analyst": {"tickets:read", "tickets:create", "tickets:comment"},
    "admin": {"tickets:read", "tickets:create", "tickets:comment", "admin:export_audit"},
}

def roles_from_claims(claims: dict) -> List[str]:
    groups = claims.get("groups", []) or []
    roles = set()
    for gid in groups:
        role = GROUP_TO_ROLE.get(gid)
        if role:
            roles.add(role)
    # default role if none
    return sorted(list(roles)) if roles else ["viewer"]

def require_perm(claims: dict, perm: str) -> None:
    roles = roles_from_claims(claims)
    allowed = set()
    for r in roles:
        allowed |= ROLE_PERMS.get(r, set())

    if perm not in allowed:
        raise HTTPException(status_code=403, detail=f"Missing permission: {perm}")
