"""OAuth callback success path: a returning user signs in again (#121).

A real callback gets a fresh session per request, so a returning user's
OAuthAccount is loaded from the database with nothing else in memory. The
shared test session would hide that (the user from the first login is still
in its identity map), so the test drops the session's objects between the
two logins.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.oauth_account import OAuthAccount
from kalekit.redis import get_redis


class _FakeProvider:
    async def exchange_code(self, code: str, code_verifier: str | None = None):
        return {"access_token": "provider-token"}

    async def get_user_info(self, access_token: str) -> dict:
        return {"id": 424242, "email": "cb@example.com", "name": "Cb"}


async def _callback(client: AsyncClient, state: str):
    r = await get_redis()
    await r.set(f"oauth_state:{state}", "github", ex=60)
    return await client.get(
        "/v1/oauth/github/callback", params={"code": "c", "state": state}
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_logs_in_new_then_returning_user(
    client: AsyncClient, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "kalekit.oauth.endpoints._get_provider", lambda provider: _FakeProvider()
    )

    first = await _callback(client, "state-121-a")
    assert first.status_code == 200, first.text
    assert first.json()["access_token"]

    # Simulate the next request's fresh session: nothing cached in memory.
    await session.flush()
    session.expunge_all()

    second = await _callback(client, "state-121-b")
    assert second.status_code == 200, second.text
    assert second.json()["access_token"]

    accounts = (
        (
            await session.execute(
                select(OAuthAccount).where(OAuthAccount.account_id == "424242")
            )
        )
        .scalars()
        .all()
    )
    assert len(accounts) == 1
