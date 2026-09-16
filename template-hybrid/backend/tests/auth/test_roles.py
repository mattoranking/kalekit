from kalekit.auth.roles import ROLE_PERMISSIONS, role_has_permission
from kalekit.models.organization import MemberRole


def test_viewer_has_only_read_permissions() -> None:
    assert role_has_permission(MemberRole.viewer, "chat:read")
    assert role_has_permission(MemberRole.viewer, "members:read")
    assert not role_has_permission(MemberRole.viewer, "chat:write")
    assert not role_has_permission(MemberRole.viewer, "chat:delete")
    assert not role_has_permission(MemberRole.viewer, "members:invite")


def test_member_can_write_but_not_delete_or_invite() -> None:
    assert role_has_permission(MemberRole.member, "chat:write")
    assert not role_has_permission(MemberRole.member, "chat:delete")
    assert not role_has_permission(MemberRole.member, "members:invite")


def test_admin_can_delete_and_invite_but_not_transfer_org() -> None:
    assert role_has_permission(MemberRole.admin, "chat:delete")
    assert role_has_permission(MemberRole.admin, "members:invite")
    assert role_has_permission(MemberRole.admin, "members:manage")
    assert not role_has_permission(MemberRole.admin, "org:delete")
    assert not role_has_permission(MemberRole.admin, "org:transfer")


def test_owner_has_every_permission_every_other_role_has() -> None:
    for role in (MemberRole.viewer, MemberRole.member, MemberRole.admin):
        assert ROLE_PERMISSIONS[role] <= ROLE_PERMISSIONS[MemberRole.owner]
    assert role_has_permission(MemberRole.owner, "org:delete")
    assert role_has_permission(MemberRole.owner, "org:transfer")


def test_unknown_permission_is_denied_for_every_role() -> None:
    for role in MemberRole:
        assert not role_has_permission(role, "org:nuke-from-orbit")
