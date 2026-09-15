from kalekit.models.organization import MemberRole

# Weakest to strongest. This ranking — not a DB permission table — is
# the entire "what can this role do" logic for this starter kit.
_ROLE_RANK: dict[MemberRole, int] = {
    MemberRole.viewer: 0,
    MemberRole.member: 1,
    MemberRole.admin: 2,
    MemberRole.owner: 3,
}


def role_at_least(role: MemberRole, minimum: MemberRole) -> bool:
    return _ROLE_RANK[role] >= _ROLE_RANK[minimum]
