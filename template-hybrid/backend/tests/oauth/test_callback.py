"""OAuth callback: login works and no provider token is persisted (#117)."""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.models.oauth_account import OAuthAccount
from kalekit.redis import get_redis


class _FakeProvider:
    async def exchange_code(self, code: str, code_verifier: str | None = None):
        return {
            "access_token": "provider-secret-a",
            "refresh_token": "provider-secret-r",
        }

    async def get_user_info(self, access_token: str) -> dict:
        return {"id": 424242, "email": "cb@example.com", "name": "Cb"}


async def _callback(client: AsyncClient, state: str):
    r = await get_redis()
    await r.set(f"oauth_state:{state}", "github", ex=60)
    return await client.get(
        "/v1/oauth/github/callback", params={"code": "c", "state": state}
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_callback_logs_in_new_and_returning_user_without_storing_tokens(
    client: AsyncClient, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "kalekit.oauth.endpoints._get_provider", lambda provider: _FakeProvider()
    )

    first = await _callback(client, "state-117-a")
    second = await _callback(client, "state-117-b")

    assert first.status_code == 200
    assert first.json()["access_token"]
    assert second.status_code == 200
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
    assert not hasattr(accounts[0], "access_token")
    assert not hasattr(accounts[0], "refresh_token")
