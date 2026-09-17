"""Regression coverage for a refresh-token double-rotation race.

`/auth/refresh` looks up the presented token, checks it's not already
revoked/expired, then rotates it (inserts a successor row and marks the
presented row revoked with `replaced_by` pointing at the successor).
Without a DB-level lock serializing that read against a concurrent
refresh of the *same* token, two truly concurrent requests can both
read `revoked=False` before either commits, both rotate, and leave two
active successor tokens in the family instead of one canonical chain --
undermining the reuse-detection chain the grace window depends on. The
existing Redis-backed grace window only catches a *replay* of an
already-committed rotation; it doesn't stop two rotations racing
against the same still-active row.

A purely timing-based test (two real HTTP requests raced with
`asyncio.gather`) can't reliably reproduce or disprove this: whether
both coroutines' fetches actually land before either commits depends
on scheduler/IO timing that isn't controllable from a test. Instead,
this test forces the exact interleaving deterministically: the first
request's locked fetch (`lock_refresh_token_by_hash`) is paused right
after it acquires the row lock (before its transaction commits), the
second request's own connection is then started and asserted to
genuinely block on the same lock (not proceed) within a short timeout,
and only then is the first request allowed to finish. If the lock is
real, the second request cannot possibly observe the pre-rotation
state -- proven here by a bounded wait that would time out if the two
requests were actually running unserialized.
"""

import asyncio
import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import kalekit.auth.repository as auth_repository
from kalekit.auth.repository import create_user, store_refresh_token
from kalekit.auth.service import generate_refresh_token, hash_refresh_token


async def _refresh_with_own_session(
    engine: AsyncEngine, refresh_token: str
) -> Response:
    """Issue one `POST /auth/refresh` call over its own dedicated
    `AsyncSession` (its own DB connection) and its own FastAPI app
    instance, mirroring how two independent, simultaneous production
    requests would each get their own per-request session/connection.

    Using the shared `client`/`session` fixtures from conftest would
    defeat the point of this test: they wire every request in a test
    to the *same* `AsyncSession`, so two "concurrent" calls through
    them are actually serialized on one connection and can never race
    -- or block on a row lock -- at the database level.
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
async def committed_refresh_token(engine: AsyncEngine) -> str:
    """A committed user with a fresh, not-yet-rotated refresh token,
    committed for real on its own connection -- the race below opens
    independent connections that need to actually see this data, unlike
    the function-scoped `session` fixture used elsewhere (which only
    ever rolls back).
    """
    suffix = uuid.uuid4().hex[:8]
    async with AsyncSession(engine, expire_on_commit=False) as setup_session:
        user = await create_user(
            setup_session, f"race-refresh-{suffix}@example.com", "password123"
        )
        raw_token, expires_at = generate_refresh_token()
        await store_refresh_token(
            setup_session,
            user_id=user.id,
            token_hash=hash_refresh_token(raw_token),
            expires_at=expires_at,
        )
        await setup_session.commit()
        return raw_token


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_refresh_of_same_token_is_serialized_by_a_row_lock(
    engine: AsyncEngine,
    committed_refresh_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two truly concurrent /auth/refresh calls presenting the same
    not-yet-rotated token, each on its own connection/session/
    transaction (a real race, not two calls sharing one AsyncSession).

    The first request's `lock_refresh_token_by_hash` call is patched to
    signal once it has acquired the row lock, then pause (holding its
    transaction -- and the lock -- open) until the test releases it.
    While paused, the second request is started on its own connection
    and must NOT be able to complete its own locked fetch of the same
    row within a short bounded wait -- proving the second request is
    genuinely blocked at the database level, not just "hasn't happened
    to run yet". Only after that's confirmed is the first request
    allowed to finish (commit its rotation); the second then
    unblocks, sees the now-already-rotated row, and -- thanks to the
    grace window -- gets back the *same* new token pair as the first,
    rather than forking the family into two independently-valid
    successor tokens.
    """
    refresh_token = committed_refresh_token

    original_lock = auth_repository.lock_refresh_token_by_hash
    first_has_lock = asyncio.Event()
    release_first = asyncio.Event()
    call_count = 0

    async def _lock_then_pause(session, token_hash):
        nonlocal call_count
        call_count += 1
        row = await original_lock(session, token_hash)
        if call_count == 1:
            first_has_lock.set()
            await release_first.wait()
        return row

    monkeypatch.setattr(auth_repository, "lock_refresh_token_by_hash", _lock_then_pause)
    # endpoints.py imported the name directly, so it must be patched
    # there too -- patching only the repository module wouldn't affect
    # the already-bound reference endpoints.py holds.
    import kalekit.auth.endpoints as auth_endpoints

    monkeypatch.setattr(
        auth_endpoints, "lock_refresh_token_by_hash", _lock_then_pause
    )

    task_a = asyncio.create_task(_refresh_with_own_session(engine, refresh_token))
    task_b: asyncio.Task[Response] | None = None
    try:
        await asyncio.wait_for(first_has_lock.wait(), timeout=5)

        task_b = asyncio.create_task(_refresh_with_own_session(engine, refresh_token))

        # Bounded wait, not a hope-it-races sleep: if the row lock is
        # working, task_b's own locked fetch is stuck behind it at the
        # database level and genuinely cannot finish yet.
        done, pending = await asyncio.wait({task_b}, timeout=1.5)
        assert task_b in pending, (
            "the second refresh completed while the first still held "
            "the row lock -- the rotation path is not actually "
            "serialized"
        )

        release_first.set()

        response_a = await asyncio.wait_for(task_a, timeout=5)
        response_b = await asyncio.wait_for(task_b, timeout=5)

        assert response_a.status_code == 200, response_a.text
        assert response_b.status_code == 200, response_b.text
        # Exactly one rotation happened -- the second, serialized
        # request observed the already-rotated row and (within the
        # default grace window) got back the identical pair the first
        # minted, instead of forking the family into two independently
        # -valid successors.
        assert response_a.json() == response_b.json()
    finally:
        # If an assertion above fired before `release_first.set()` (or
        # before task_b even existed), task_a -- and possibly task_b --
        # would otherwise be left forever awaiting an Event nothing
        # will ever set, holding a real DB connection open and hanging
        # the rest of the suite/teardown. Always unstick and reap them.
        release_first.set()
        for task in (task_a, task_b):
            if task is not None and not task.done():
                task.cancel()
        for task in (task_a, task_b):
            if task is not None:
                try:
                    await task
                except (Exception, asyncio.CancelledError):
                    pass
