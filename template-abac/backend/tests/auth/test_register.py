import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_register_creates_a_personal_organization(register) -> None:
    """There's no such thing as a tenant-less user in this style --
    every sign-up creates (or joins) at least one organization."""
    response = await register("alice@example.com")

    assert response.status_code == 201
    organizations = response.json()["organizations"]
    assert len(organizations) == 1
    assert organizations[0]["name"] == "alice's workspace"
    assert "id" in organizations[0]


@pytest.mark.asyncio(loop_scope="session")
async def test_register_accepts_a_custom_organization_name(register) -> None:
    response = await register("alice@example.com", organization_name="Acme Inc")

    assert response.status_code == 201
    organizations = response.json()["organizations"]
    assert len(organizations) == 1
    assert organizations[0]["name"] == "Acme Inc"
    assert "id" in organizations[0]


@pytest.mark.asyncio(loop_scope="session")
async def test_duplicate_email_is_rejected(register) -> None:
    await register("dup@example.com")
    response = await register("dup@example.com")

    assert response.status_code == 409
