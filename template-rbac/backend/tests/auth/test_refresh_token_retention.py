"""Repository-level tests for the SQL-side rewrite of
`list_user_sessions` and the new `prune_refresh_tokens` retention
helper -- see #73.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.client_type import ClientType
from kalekit.auth.repository import (
    create_user,
    list_user_sessions,
    prune_refresh_tokens,
    store_refresh_token,
)
from kalekit.models.refresh_token import RefreshToken

NOW = datetime.now(timezone.utc)


async def _make_user(session: AsyncSession, email: str) -> uuid.UUID:
    user = await create_user(session, email, "password123", email_verified=True)
    return user.id


@pytest.mark.asyncio(loop_scope="session")
async def test_list_user_sessions_uses_the_latest_usable_rows_last_used_at(
    session: AsyncSession,
) -> None:
    """Within one family, an older *usable* row can have a smaller
    last_used_at than a newer one even without real rotation timing
    quirks -- the SQL rewrite must still pick the row with the max
    last_used_at among usable rows, not merely the most recently
    created one, mirroring the old Python `max(usable, key=...)`.
    """
    user_id = await _make_user(session, "retention-latest@example.com")
    family_id = uuid.uuid4()

    first = await store_refresh_token(
        session,
        user_id,
        token_hash="hash-older",
        expires_at=NOW + timedelta(days=30),
        client=ClientType.web,
        family_id=family_id,
        family_created_at=NOW - timedelta(days=5),
        device_info="OlderDevice",
    )
    second = await store_refresh_token(
        session,
        user_id,
        token_hash="hash-newer",
        expires_at=NOW + timedelta(days=30),
        client=ClientType.web,
        family_id=family_id,
        family_created_at=NOW - timedelta(days=5),
        device_info="NewerDevice",
    )
    # Explicitly invert last_used_at from insertion order: the row
    # created *first* ("OlderDevice") is the one actually most
    # recently used. Both rows would otherwise pick up their
    # last_used_at column default at insert time, which happens to
    # already be in creation order -- that would let a buggy
    # implementation that merely picks the most-recently-*created* row
    # pass this test too. Inverting the two makes the assertion below
    # only pass if the query genuinely orders by last_used_at.
    first.last_used_at = NOW - timedelta(minutes=1)
    second.last_used_at = NOW - timedelta(minutes=10)
    await session.flush()

    summaries = await list_user_sessions(session, user_id)

    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.family_id == family_id
    # "OlderDevice" wins: it has the later last_used_at even though it
    # was created first -- proves the query orders by last_used_at, not
    # creation order.
    assert summary.device_info == "OlderDevice"
    # created_at reflects the family's absolute start, not either row's
    # own created_at.
    assert summary.created_at == NOW - timedelta(days=5)


@pytest.mark.asyncio(loop_scope="session")
async def test_list_user_sessions_ignores_dead_rows_within_a_live_family(
    session: AsyncSession,
) -> None:
    """A family with one revoked row and one live row must still be
    reported using only the live row -- the revoked row must not be
    eligible to "win" the latest-usable-row selection.
    """
    user_id = await _make_user(session, "retention-mixed@example.com")
    family_id = uuid.uuid4()

    revoked = await store_refresh_token(
        session,
        user_id,
        token_hash="hash-revoked",
        expires_at=NOW + timedelta(days=30),
        client=ClientType.web,
        family_id=family_id,
        family_created_at=NOW - timedelta(days=2),
        device_info="RevokedDevice",
    )
    revoked.revoked = True
    revoked.last_used_at = NOW + timedelta(hours=1)  # even if "later"
    await store_refresh_token(
        session,
        user_id,
        token_hash="hash-live",
        expires_at=NOW + timedelta(days=30),
        client=ClientType.web,
        family_id=family_id,
        family_created_at=NOW - timedelta(days=2),
        device_info="LiveDevice",
    )
    await session.flush()

    summaries = await list_user_sessions(session, user_id)

    assert len(summaries) == 1
    assert summaries[0].device_info == "LiveDevice"


@pytest.mark.asyncio(loop_scope="session")
async def test_prune_refresh_tokens_deletes_old_revoked_rows(
    session: AsyncSession,
) -> None:
    user_id = await _make_user(session, "prune-revoked@example.com")
    token = await store_refresh_token(
        session,
        user_id,
        token_hash="hash-old-revoked",
        expires_at=NOW + timedelta(days=30),
        client=ClientType.web,
    )
    token.revoked = True
    token.updated_at = NOW - timedelta(days=40)
    await session.flush()

    deleted = await prune_refresh_tokens(session, older_than_days=30)

    assert deleted == 1
    remaining = await session.get(RefreshToken, token.id)
    assert remaining is None


@pytest.mark.asyncio(loop_scope="session")
async def test_prune_refresh_tokens_deletes_old_naturally_expired_rows(
    session: AsyncSession,
) -> None:
    """A row that died by natural expiry (never revoked, so
    `updated_at` is still null) must fall back to `expires_at` (death
    time) for the retention clock -- it should still be prunable once
    old enough past its expiry.
    """
    user_id = await _make_user(session, "prune-expired@example.com")
    # Constructed directly (rather than via store_refresh_token + a
    # post-hoc mutation) so the single INSERT carries the desired
    # created_at without ever touching updated_at -- mutating
    # created_at on an already-flushed row would trigger an UPDATE and
    # let `onupdate` stamp updated_at, defeating the point of this
    # test (a row that was truly never touched after being issued).
    token = RefreshToken(
        user_id=user_id,
        token_hash="hash-old-expired",
        expires_at=NOW - timedelta(days=40),
        client=ClientType.web.value,
        created_at=NOW - timedelta(days=40),
    )
    session.add(token)
    await session.flush()
    assert token.updated_at is None

    deleted = await prune_refresh_tokens(session, older_than_days=30)

    assert deleted == 1
    remaining = await session.get(RefreshToken, token.id)
    assert remaining is None


@pytest.mark.asyncio(loop_scope="session")
async def test_prune_refresh_tokens_natural_death_fallback_uses_expiry(
    session: AsyncSession,
) -> None:
    """Regression test: a never-touched (never revoked/replaced) row
    must age out from when it *died* (expires_at), not from when it
    was *issued* (created_at). A long-lived session's token (e.g. the
    90-day web/mobile idle timeout, see #6) can have a created_at far
    older than the retention window while still being freshly dead --
    using created_at as the fallback would delete it the instant it
    expires instead of `older_than_days` after that.

    Simulated here with two never-touched tokens, both issued 100 days
    ago (older than the 30-day retention window many times over):
    - `recent`: expires_at only 1 day in the past (recently dead) --
      must survive at `older_than_days=30`.
    - `long_dead`: expires_at 31 days in the past -- must be pruned,
      since it's now past the retention window measured from its own
      death, not its issuance.

    Two separate rows (rather than mutating one row's expires_at
    in place) so neither assertion is confused by `onupdate` stamping
    `updated_at` on an UPDATE -- these rows must stay untouched after
    creation to exercise the "never touched" fallback path at all.
    """
    user_id = await _make_user(session, "prune-long-lived-expiry@example.com")
    recent = RefreshToken(
        user_id=user_id,
        token_hash="hash-long-lived-recently-expired",
        expires_at=NOW - timedelta(days=1),
        client=ClientType.web.value,
        created_at=NOW - timedelta(days=100),
    )
    long_dead = RefreshToken(
        user_id=user_id,
        token_hash="hash-long-lived-long-expired",
        expires_at=NOW - timedelta(days=31),
        client=ClientType.web.value,
        created_at=NOW - timedelta(days=100),
    )
    session.add_all([recent, long_dead])
    await session.flush()
    assert recent.updated_at is None
    assert long_dead.updated_at is None

    deleted = await prune_refresh_tokens(session, older_than_days=30)

    assert deleted == 1
    assert await session.get(RefreshToken, recent.id) is not None
    assert await session.get(RefreshToken, long_dead.id) is None


@pytest.mark.asyncio(loop_scope="session")
async def test_prune_refresh_tokens_keeps_recently_dead_rows(
    session: AsyncSession,
) -> None:
    """A row that died within the retention window must survive --
    only rows dead for *at least* `older_than_days` are pruned."""
    user_id = await _make_user(session, "prune-recent@example.com")
    token = await store_refresh_token(
        session,
        user_id,
        token_hash="hash-recent-revoked",
        expires_at=NOW + timedelta(days=30),
        client=ClientType.web,
    )
    token.revoked = True
    token.updated_at = NOW - timedelta(days=1)
    await session.flush()

    deleted = await prune_refresh_tokens(session, older_than_days=30)

    assert deleted == 0
    remaining = await session.get(RefreshToken, token.id)
    assert remaining is not None


@pytest.mark.asyncio(loop_scope="session")
async def test_prune_refresh_tokens_never_deletes_usable_rows(
    session: AsyncSession,
) -> None:
    """A still-usable token must never be pruned, no matter how old
    it (or its family) is -- a long-lived, regularly-rotated session
    must survive."""
    user_id = await _make_user(session, "prune-usable@example.com")
    token = RefreshToken(
        user_id=user_id,
        token_hash="hash-old-usable",
        expires_at=NOW + timedelta(days=30),
        client=ClientType.web.value,
        created_at=NOW - timedelta(days=400),
        family_created_at=NOW - timedelta(days=400),
    )
    session.add(token)
    await session.flush()

    deleted = await prune_refresh_tokens(session, older_than_days=30)

    assert deleted == 0
    remaining = await session.get(RefreshToken, token.id)
    assert remaining is not None


@pytest.mark.asyncio(loop_scope="session")
async def test_prune_refresh_tokens_rejects_negative_window(
    session: AsyncSession,
) -> None:
    """A negative `older_than_days` would make `cutoff` a *future*
    timestamp, so the delete's `retention_clock <= cutoff` check would
    hold for nearly every already-dead row regardless of how recently
    it died -- e.g. a typo'd `--older-than-days -5` would prune far
    more aggressively than intended, silently. Must raise instead of
    running, and must not delete anything on the way to raising.
    """
    user_id = await _make_user(session, "prune-negative-window@example.com")
    token = await store_refresh_token(
        session,
        user_id,
        token_hash="hash-negative-window",
        expires_at=NOW + timedelta(days=30),
        client=ClientType.web,
    )
    token.revoked = True
    token.updated_at = NOW - timedelta(days=40)
    await session.flush()

    with pytest.raises(ValueError):
        await prune_refresh_tokens(session, older_than_days=-5)

    remaining = await session.get(RefreshToken, token.id)
    assert remaining is not None
