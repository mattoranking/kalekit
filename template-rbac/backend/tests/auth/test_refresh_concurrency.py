"""Regression coverage for a double-rotation race in POST /auth/refresh.

`refresh()` is check-then-rotate: it reads a refresh token's
revoked/replaced_by state and then, if it's unrevoked, rotates it
(revokes the old row, inserts a new one carrying the same family_id).
Without a row lock on that read, two requests racing in with the
*same* token (a network retry, or two BFF instances refreshing
concurrently) could both observe `revoked=False` before either
commits, and both proceed to rotate -- producing two successor rows
from one predecessor instead of a single, well-defined rotation. The
Redis grace-window cache only smooths over a *replay* of an
already-rotated token; it does nothing to prevent this simultaneous
double-rotation, since neither request has rotated (and therefore
neither has populated the cache) at the moment both read the row.

A purely timing-based test (two real HTTP requests raced with
`asyncio.gather`) can't reliably reproduce this -- see
`test_register_concurrency.py` for the same
argument in a different race. Instead,
`get_refresh_token_by_hash_for_update` (as imported into
`kalekit.auth.endpoints`, which is what `refresh()` actually calls) is
monkeypatched so that, once the first request's `SELECT ... FOR UPDATE`
has acquired the row lock, a second, fully independent request for the
*same* token is started concurrently and asserted to still be blocked a
moment later -- deterministically proving the lock is what's serializing
them, not scheduler luck.
"""

import asyncio
import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import kalekit.auth.endpoints as auth_endpoints
from kalekit.auth.client_type import ClientType
from kalekit.auth.repository import (
    create_user,
    get_refresh_token_by_hash,
    store_refresh_token,
)
from kalekit.auth.service import generate_refresh_token, hash_refresh_token
from kalekit.models.refresh_token import RefreshToken
from kalekit.models.user import User


async def _refresh_with_own_session(
    engine: AsyncEngine, refresh_token: str
) -> Response:
    """POST /v1/auth/refresh over its own dedicated `AsyncSession` (its
    own DB connection/transaction) and its own FastAPI app instance,
    mirroring how two independent, simultaneous production requests
    would each get their own per-request session/connection -- required
    for the row lock taken by one to actually block the other, which
    the shared `client`/`session` conftest fixtures (one connection for
    every "concurrent" call) cannot exercise.
    """
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

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(
            "/v1/auth/refresh", json={"refresh_token": refresh_token}
        )


@pytest_asyncio.fixture(loop_scope="session")
async def committed_refresh_token(engine: AsyncEngine) -> AsyncGenerator[str]:
    """A user + refresh token *committed* to the database, so that
    independent connections can see them. The shared `session` fixture
    rolls back and can't be used here; instead this fixture deletes
    what it committed, so the rows don't leak into other tests (e.g.
    ones that count users).
    """
    suffix = uuid.uuid4().hex[:8]
    async with AsyncSession(engine, expire_on_commit=False) as setup_session:
        user = await create_user(
            setup_session, f"refresh-race-{suffix}@example.com", "password12345"
        )
        refresh_token, expires_at = generate_refresh_token()
        await store_refresh_token(
            setup_session,
            user_id=user.id,
            token_hash=hash_refresh_token(refresh_token),
            expires_at=expires_at,
            client=ClientType.web,
        )
        await setup_session.commit()
        user_id = user.id

    yield refresh_token

    async with AsyncSession(engine) as cleanup_session:
        await cleanup_session.execute(
            delete(RefreshToken).where(RefreshToken.user_id == user_id)
        )
        await cleanup_session.execute(delete(User).where(User.id == user_id))
        await cleanup_session.commit()


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_refresh_of_the_same_token_does_not_double_rotate(
    engine: AsyncEngine,
    committed_refresh_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forces a second, fully independent /auth/refresh call for the
    same token to start while the first still holds the row's
    `FOR UPDATE` lock (uncommitted). The second call must block until
    the first commits, then see the row as already rotated -- landing
    on the grace-window path and returning the *same* pair the first
    call got, not an independently rotated second pair. Exactly one new
    row must exist in the family afterward.
    """
    refresh_token = committed_refresh_token
    original_lock = auth_endpoints.get_refresh_token_by_hash_for_update
    second_call: dict[str, asyncio.Task[Response]] = {}
    call_count = 0

    async def _lock_then_race(session, token_hash):
        nonlocal call_count
        call_count += 1
        this_call = call_count
        token_row = await original_lock(session, token_hash)
        # Only the *first* call (the original request) spawns a second,
        # racing request -- without this guard, every subsequent call
        # (the second request's own call to this patched function, once
        # it unblocks) would spawn yet another one in turn, chaining
        # into an unbounded, never-awaited sequence of background
        # refresh requests instead of the single deterministic race
        # this test means to set up.
        if this_call == 1:
            # The row lock is now held by this (uncommitted)
            # transaction. Kick off a second, independent refresh for
            # the same token -- it must block on the same lock rather
            # than racing through.
            task = asyncio.create_task(_refresh_with_own_session(engine, refresh_token))
            await asyncio.sleep(0.2)
            assert not task.done(), (
                "second concurrent /auth/refresh call for the same "
                "token completed before the first committed -- the "
                "row lock isn't serializing rotation"
            )
            second_call["task"] = task
        return token_row

    monkeypatch.setattr(
        auth_endpoints, "get_refresh_token_by_hash_for_update", _lock_then_race
    )

    first_response = await _refresh_with_own_session(engine, refresh_token)
    assert first_response.status_code == 200

    second_response = await second_call["task"]
    assert second_response.status_code == 200

    # The second call only unblocked once the first had committed its
    # rotation -- it must land on the grace-window replay path (the
    # direct predecessor, replayed within the window) and get back the
    # identical pair, not a second, independently minted rotation.
    assert second_response.json() == first_response.json()

    async with AsyncSession(engine, expire_on_commit=False) as verify_session:
        original_row = await get_refresh_token_by_hash(
            verify_session, hash_refresh_token(refresh_token)
        )
        assert original_row is not None
        family_id = original_row.family_id

        count_result = await verify_session.execute(
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.family_id == family_id)
        )
        # The original row plus exactly one rotation -- not two,
        # which is what a double-rotation race would have produced.
        assert count_result.scalar_one() == 2
