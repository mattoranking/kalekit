import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_creator_becomes_owner(register) -> None:
    """The person who creates an organization is always its owner, and
    the registration response reports that role directly."""
    response = await register("owner@example.com")
    assert response.status_code == 201

    organizations = response.json()["organizations"]
    assert len(organizations) == 1
    assert organizations[0]["name"] == "My workspace"
    assert organizations[0]["role"] == "owner"


@pytest.mark.asyncio(loop_scope="session")
async def test_register_default_organization_name_does_not_leak_email(
    register,
) -> None:
    """The default org name must never be derived from the email address --
    it becomes visible to anyone later invited to the organization."""
    response = await register("bob@example.com")

    assert response.status_code == 201
    organizations = response.json()["organizations"]
    assert "bob" not in organizations[0]["name"].lower()


@pytest.mark.asyncio(loop_scope="session")
async def test_duplicate_email_is_rejected(register) -> None:
    await register("dup@example.com")
    response = await register("dup@example.com")

    assert response.status_code == 409
