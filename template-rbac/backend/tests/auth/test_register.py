import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_first_user_becomes_admin(register) -> None:
    """The very first user in a fresh database is auto-promoted to admin
    so there's a working example immediately, without a seed script."""
    response = await register("admin@example.com")

    assert response.status_code == 201
    assert response.json()["roles"] == ["admin"]


@pytest.mark.asyncio(loop_scope="session")
async def test_subsequent_users_become_visitor(register) -> None:
    await register("first@example.com")
    response = await register("second@example.com")

    assert response.status_code == 201
    assert response.json()["roles"] == ["visitor"]


@pytest.mark.asyncio(loop_scope="session")
async def test_duplicate_email_is_rejected(register) -> None:
    await register("dup@example.com")
    response = await register("dup@example.com")

    assert response.status_code == 409
