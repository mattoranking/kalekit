"""A refresh racing a password reset or logout-all must not leave a
working session (#240).

`revoke_user_refresh_tokens` revokes the tokens it SELECTed, without a
lock. A refresh in flight inserts its new row after that SELECT, so the
row is never revoked. Each refresh-token row now stores the user's
`token_version` it was minted under, and /auth/refresh refuses (401,
family revoked) a row older than the user's current version. The racing
row carries the old version, so its first use is refused.

The interleaving is forced, not left to timing. The refresh runs on its
own connection and pauses just before it inserts its new row (the user
was read already, at the old version). The security action runs on
another connection: its revoke SELECT sees only committed rows, and its
UPDATE of the old row then blocks on the refresh's row lock. The refresh
is released once the SELECT has run (a SQLAlchemy cursor event), so its
new row always lands after the snapshot.
"""

import asyncio
import uuid
from collections.abc import AsyncGenerator, Callable, Coroutine
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import kalekit.auth.endpoints as auth_endpoints
from kalekit.auth.client_type import ClientType
from kalekit.auth.repository import (
    create_password_reset_token,
    create_user,
    find_user_by_email,
    get_refresh_token_by_hash,
    store_refresh_token,
)
from kalekit.auth.service import (
    create_access_token,
    generate_refresh_token,
    generate_verification_token,
    hash_refresh_token,
    hash_verification_token,
    password_reset_token_expiry,
)
from kalekit.models.refresh_token import RefreshToken
from kalekit.models.user import User
from tests.auth.test_redis_revocation_guards import _login

_OLD = "old-password123"
_NEW = "new-password456"


def _own_app(engine: AsyncEngine):
    """An app whose requests each use their own committed connection."""
    from kalekit.main import create_app
    from kalekit.postgres import get_db_read_session, get_db_session

    app = create_app()

    async def _session() -> AsyncGenerator[AsyncSession]:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[get_db_read_session] = _session
    return app


async def _post(engine: AsyncEngine, path: str, **kwargs: Any) -> Response:
    transport = ASGITransport(app=_own_app(engine))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(path, **kwargs)


def _signal_after_revoke_snapshot(engine: AsyncEngine, event: asyncio.Event):
    """Set `event` once the revoke's SELECT of the user's refresh tokens
    has run, i.e. once its snapshot is taken."""
    from sqlalchemy import event as sa_event

    def _after(conn, cursor, statement, parameters, context, executemany):
        if "FROM refresh_tokens WHERE refresh_tokens.user_id" in " ".join(
            statement.split()
        ):
            event.set()

    sa_event.listen(engine.sync_engine, "after_cursor_execute", _after)
    return lambda: sa_event.remove(engine.sync_engine, "after_cursor_execute", _after)


class _Account:
    def __init__(
        self, user_id: uuid.UUID, refresh_token: str, access_token: str
    ) -> None:
        self.user_id = user_id
        self.refresh_token = refresh_token
        self.access_token = access_token


@pytest_asyncio.fixture(loop_scope="session")
async def committed_account(engine: AsyncEngine) -> AsyncGenerator[_Account]:
    """A user with one session, committed so other connections see it."""
    suffix = uuid.uuid4().hex[:8]
    async with AsyncSession(engine, expire_on_commit=False) as setup:
        user = await create_user(setup, f"refresh-ver-{suffix}@example.com", _OLD)
        refresh_token, expires_at = generate_refresh_token()
        row = await store_refresh_token(
            setup,
            user_id=user.id,
            token_hash=hash_refresh_token(refresh_token),
            expires_at=expires_at,
            client=ClientType.web,
            token_version=user.token_version,
        )
        access_token = create_access_token(
            str(user.id),
            [],
            token_version=user.token_version,
            session_id=str(row.family_id),
        )
        await setup.commit()
        user_id = user.id

    yield _Account(user_id, refresh_token, access_token)

    async with AsyncSession(engine) as cleanup:
        await cleanup.execute(
            text("delete from password_reset_tokens where user_id = :u"),
            {"u": user_id},
        )
        await cleanup.execute(
            delete(RefreshToken).where(RefreshToken.user_id == user_id)
        )
        await cleanup.execute(delete(User).where(User.id == user_id))
        await cleanup.commit()


async def _logout_all(engine: AsyncEngine, account: _Account) -> Response:
    return await _post(
        engine,
        "/v1/auth/logout-all",
        headers={"Authorization": f"Bearer {account.access_token}"},
    )


async def _reset_password(engine: AsyncEngine, account: _Account) -> Response:
    raw = generate_verification_token()
    async with AsyncSession(engine) as session:
        await create_password_reset_token(
            session,
            user_id=account.user_id,
            token_hash=hash_verification_token(raw),
            expires_at=password_reset_token_expiry(),
        )
        await session.commit()
    return await _post(
        engine,
        "/v1/auth/password/reset",
        json={"token": raw, "new_password": _NEW},
    )


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("action", [_logout_all, _reset_password])
async def test_a_token_minted_by_a_racing_refresh_is_refused_after_the_action(
    engine: AsyncEngine,
    committed_account: _Account,
    monkeypatch: pytest.MonkeyPatch,
    action: Callable[[AsyncEngine, _Account], Coroutine[None, None, Response]],
) -> None:
    account = committed_account
    reached_insert = asyncio.Event()
    release = asyncio.Event()
    real_store = auth_endpoints.store_refresh_token

    async def _pause_before_insert(*args: Any, **kwargs: Any):
        reached_insert.set()
        await release.wait()
        return await real_store(*args, **kwargs)

    monkeypatch.setattr(auth_endpoints, "store_refresh_token", _pause_before_insert)

    refresh = asyncio.create_task(
        _post(engine, "/v1/auth/refresh", json={"refresh_token": account.refresh_token})
    )
    await asyncio.wait_for(reached_insert.wait(), timeout=10)
    # The refresh holds the old row's lock and has read the user.
    snapshot_taken = asyncio.Event()
    stop_listening = _signal_after_revoke_snapshot(engine, snapshot_taken)
    security_action = asyncio.create_task(action(engine, account))
    await asyncio.wait_for(snapshot_taken.wait(), timeout=10)
    stop_listening()
    release.set()

    refreshed = await asyncio.wait_for(refresh, timeout=10)
    acted = await asyncio.wait_for(security_action, timeout=10)
    assert refreshed.status_code == 200
    assert acted.status_code in (200, 204)

    # The racing refresh's new token was inserted after the action's
    # snapshot, so it is still unrevoked in the database...
    async with AsyncSession(engine) as check:
        racing_row = await get_refresh_token_by_hash(
            check, hash_refresh_token(refreshed.json()["refresh_token"])
        )
        assert racing_row is not None
        assert racing_row.revoked is False

    # ...but it must not work.
    again = await _post(
        engine,
        "/v1/auth/refresh",
        json={"refresh_token": refreshed.json()["refresh_token"]},
    )
    assert again.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_a_row_older_than_the_user_version_is_refused_and_revokes_the_family(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("refresh-stale-ver@example.com", _OLD)
    tokens = await _login(client, "refresh-stale-ver@example.com", _OLD)
    user = await find_user_by_email(session, "refresh-stale-ver@example.com")
    assert user is not None
    user.token_version = user.token_version + 1
    await session.flush()

    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )

    assert response.status_code == 401
    row = await get_refresh_token_by_hash(
        session, hash_refresh_token(tokens["refresh_token"])
    )
    assert row is not None
    assert row.revoked is True


@pytest.mark.asyncio(loop_scope="session")
async def test_rotation_keeps_the_row_at_the_current_version(
    client: AsyncClient, register, session: AsyncSession
) -> None:
    await register("refresh-rotate-ver@example.com", _OLD)
    tokens = await _login(client, "refresh-rotate-ver@example.com", _OLD)

    refreshed = await client.post(
        "/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )

    assert refreshed.status_code == 200
    row = await get_refresh_token_by_hash(
        session, hash_refresh_token(refreshed.json()["refresh_token"])
    )
    assert row is not None
    assert row.token_version == 0


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_caller_still_refreshes_twice(
    client: AsyncClient, register, auth_header
) -> None:
    await register("refresh-ver-caller@example.com", _OLD)
    caller = await _login(client, "refresh-ver-caller@example.com", _OLD)
    other = await _login(client, "refresh-ver-caller@example.com", _OLD)
    changed = await client.post(
        "/v1/auth/change-password",
        headers=auth_header(caller["access_token"]),
        json={"current_password": _OLD, "new_password": _NEW},
    )
    assert changed.status_code == 200

    first = await client.post(
        "/v1/auth/refresh", json={"refresh_token": caller["refresh_token"]}
    )
    assert first.status_code == 200
    # The rotated token works as well, not just the one the caller held.
    second = await client.post(
        "/v1/auth/refresh", json={"refresh_token": first.json()["refresh_token"]}
    )
    assert second.status_code == 200
    # Every other session is gone.
    gone = await client.post(
        "/v1/auth/refresh", json={"refresh_token": other["refresh_token"]}
    )
    assert gone.status_code == 401


@pytest.mark.asyncio(loop_scope="session")
async def test_a_role_change_does_not_end_the_users_sessions(
    client: AsyncClient, register, promote_to_admin, login, auth_header
) -> None:
    """A role change bumps the version without revoking anything, so the
    user's refresh tokens must follow the new version."""
    await register("refresh-ver-admin@example.com")
    await promote_to_admin("refresh-ver-admin@example.com")
    admin_token = await login("refresh-ver-admin@example.com", client_type="admin")
    await register("refresh-ver-bob@example.com")
    bob = await _login(client, "refresh-ver-bob@example.com", "password12345")
    bob_id = (
        await client.get("/v1/auth/me", headers=auth_header(bob["access_token"]))
    ).json()["id"]

    changed = await client.put(
        f"/v1/users/{bob_id}/roles",
        headers=auth_header(admin_token),
        json={"roles": ["visitor", "admin"]},
    )
    assert changed.status_code == 200

    refreshed = await client.post(
        "/v1/auth/refresh", json={"refresh_token": bob["refresh_token"]}
    )
    assert refreshed.status_code == 200
    me = await client.get(
        "/v1/auth/me", headers=auth_header(refreshed.json()["access_token"])
    )
    assert me.status_code == 200
