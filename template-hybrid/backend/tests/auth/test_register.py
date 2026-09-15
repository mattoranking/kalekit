import pytest
from sqlalchemy import select


@pytest.mark.asyncio(loop_scope="session")
async def test_creator_becomes_owner(register, org_id_for, session) -> None:
    """The person who creates an organization is always its owner --
    this is a claim about the *membership*, not something /auth/me's
    plain name list can show, so we check the row directly."""
    from kalekit.models.organization import MemberRole, OrganizationMember

    response = await register("owner@example.com")
    assert response.status_code == 201
    assert response.json()["organizations"] == ["owner's workspace"]

    org_id = await org_id_for("owner@example.com")
    result = await session.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id
        )
    )
    membership = result.scalar_one()
    assert membership.role == MemberRole.owner


@pytest.mark.asyncio(loop_scope="session")
async def test_duplicate_email_is_rejected(register) -> None:
    await register("dup@example.com")
    response = await register("dup@example.com")

    assert response.status_code == 409
