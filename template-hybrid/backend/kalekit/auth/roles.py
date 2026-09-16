from kalekit.models.organization import MemberRole

# Weakest to strongest. Used only for role-to-role comparisons (e.g. "can I
# grant a role at or below my own?") — it is deliberately NOT used to decide
# whether an endpoint should be reachable; see ROLE_PERMISSIONS below for
# that. Because it assumes roles are strictly nested, it is the wrong tool
# for a non-linear role (e.g. a `billing` role that can manage invoices but
# not delete messages).
_ROLE_RANK: dict[MemberRole, int] = {
    MemberRole.viewer: 0,
    MemberRole.member: 1,
    MemberRole.admin: 2,
    MemberRole.owner: 3,
}


def role_at_least(role: MemberRole, minimum: MemberRole) -> bool:
    return _ROLE_RANK[role] >= _ROLE_RANK[minimum]


# What each role can do, in one place. Endpoints should declare the
# permission they require (`require_org_permission("chat:delete")`) rather
# than a minimum role (`require_org_role(MemberRole.admin)`) — adding a
# non-linear role, or moving a capability between roles, then only means
# editing this mapping instead of every call site.
#
# The four roles stay linear/cumulative for this starter kit (that's the
# Hybrid template's design), so each role's set is built on the one below
# it, but nothing about `require_org_permission` requires that to stay true.
_VIEWER_PERMISSIONS: frozenset[str] = frozenset({"chat:read", "members:read"})
_MEMBER_PERMISSIONS: frozenset[str] = _VIEWER_PERMISSIONS | {"chat:write"}
_ADMIN_PERMISSIONS: frozenset[str] = _MEMBER_PERMISSIONS | {
    "chat:delete",
    "members:invite",
    "members:manage",
}
_OWNER_PERMISSIONS: frozenset[str] = _ADMIN_PERMISSIONS | {"org:delete", "org:transfer"}

ROLE_PERMISSIONS: dict[MemberRole, frozenset[str]] = {
    MemberRole.viewer: _VIEWER_PERMISSIONS,
    MemberRole.member: _MEMBER_PERMISSIONS,
    MemberRole.admin: _ADMIN_PERMISSIONS,
    MemberRole.owner: _OWNER_PERMISSIONS,
}


def role_has_permission(role: MemberRole, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS[role]
