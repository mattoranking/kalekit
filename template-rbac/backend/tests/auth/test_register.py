import pytest


@pytest.mark.asyncio(loop_scope="session")
async def test_first_user_does_not_become_admin(register) -> None:
    """Nobody is auto-promoted to admin, not even the first registrant in a
    fresh database -- that would let whoever registers first on a freshly
    deployed instance own the system, and a race between two simultaneous
    signups could grant it non-deterministically. Admin is only granted via
    `python -m kalekit.cli create-admin` (see kalekit/cli.py)."""
    response = await register("first@example.com")

    assert response.status_code == 201
    assert response.json()["roles"] == ["visitor"]


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
