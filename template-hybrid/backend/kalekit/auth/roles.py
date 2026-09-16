from kalekit.models.organization import MemberRole

# What each role can do, in one place. Endpoints should declare the
# permission they require (`require_org_permission("chat:delete")`) rather
# than a minimum role, so adding a non-linear role, or moving a capability
# between roles, only means editing this mapping instead of every call site.
#
# Grant-eligibility ("can I invite someone at role X?") is itself modeled as
# a permission per grantable role (`members:grant:<role>`) rather than a
# rank comparison -- see `organization/endpoints.py::add_organization_member`.
# Only admin/owner can invite at all (gated by `members:invite`), so viewer
# and member carry no `members:grant:*` permissions.
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
    "members:grant:viewer",
    "members:grant:member",
    "members:grant:admin",
}
_OWNER_PERMISSIONS: frozenset[str] = _ADMIN_PERMISSIONS | {
    "org:delete",
    "org:transfer",
    "members:grant:owner",
}

ROLE_PERMISSIONS: dict[MemberRole, frozenset[str]] = {
    MemberRole.viewer: _VIEWER_PERMISSIONS,
    MemberRole.member: _MEMBER_PERMISSIONS,
    MemberRole.admin: _ADMIN_PERMISSIONS,
    MemberRole.owner: _OWNER_PERMISSIONS,
}


def role_has_permission(role: MemberRole, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS[role]
