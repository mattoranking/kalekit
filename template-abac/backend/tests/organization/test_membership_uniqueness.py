"""Regression coverage for the concurrent-invite IntegrityError bug.

`add_member` is check-then-insert against `OrganizationMember`, which
already carries a `UniqueConstraint("organization_id", "user_id")`. Two
concurrent invites of the same user into the same org could both pass the
"does not exist yet" check and race the insert, leaving the loser with an
unhandled `IntegrityError` -> 500 instead of the clean 409 the endpoint
promises. See issue #56.

Direct membership adds went away with issue #24's invitation flow, so
this now races two concurrent `POST /invitations/accept` calls against
the *same* invitation token instead of two `POST .../members` calls --
`add_member`'s check-then-insert is exercised the same way either path
gets there.
"""

import asyncio
import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.repository import create_user
from kalekit.auth.service import create_access_token
from kalekit.models.organization import OrganizationMember
from kalekit.organization.repository import (
    add_member,
    create_invitation,
    create_organization,
)
from kalekit.organization.service import (
    generate_invitation_token,
    hash_invitation_token,
    invitation_token_expiry,
)


async def _accept_with_own_session(
    engine: AsyncEngine, token: str, raw_invitation_token: str
) -> Response:
    """Issue one `POST /invitations/accept` call over its own dedicated
    `AsyncSession` (its own DB connection) and its own FastAPI app
    instance, mirroring how two independent, simultaneous production
    requests would each get their own per-request session.

    Using the shared `client`/`session` fixtures from conftest would
    defeat the point of this test: they wire every request in a test to
    the *same* `AsyncSession`, so two "concurrent" calls through them are
    actually serialized on one connection and can never race at the
    database level.
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
            "/v1/invitations/accept",
            json={"token": raw_invitation_token},
            headers={"Authorization": f"Bearer {token}"},
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_reaccepting_a_consumed_invitation_returns_400(
    client,
    session: AsyncSession,
    register,
    login,
    auth_header,
    org_id_for,
) -> None:
    """Sequential duplicate accept: the second call against the *same*
    token must be rejected (single-use), and the roster must still show
    exactly the two original members -- no second row created."""
    await register("owner@example.com")
    await register("member@example.com")
    token_owner = await login("owner@example.com")
    token_member = await login("member@example.com")
    org = await org_id_for("owner@example.com")

    raw_token = generate_invitation_token()
    await create_invitation(
        session,
        organization_id=uuid.UUID(org),
        email="member@example.com",
        token_hash=hash_invitation_token(raw_token),
        invited_by=None,
        expires_at=invitation_token_expiry(),
    )

    first = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_member),
    )
    assert first.status_code == 201

    second = await client.post(
        "/v1/invitations/accept",
        json={"token": raw_token},
        headers=auth_header(token_member),
    )
    assert second.status_code == 400

    roster = await client.get(
        f"/v1/organizations/{org}/members", headers=auth_header(token_owner)
    )
    assert len(roster.json()["items"]) == 2


@pytest_asyncio.fixture(loop_scope="session")
async def committed_owner_org_and_invitation(
    engine: AsyncEngine,
) -> tuple[str, str, str]:
    """An organization (with a committed owner membership) plus a second,
    not-yet-a-member user and a valid, committed invitation for them --
    all committed on their own session.

    The race test below spins up independent `AsyncSession`s of its own
    (their own DB connections) to exercise a real concurrent insert. Those
    connections can't see data that only exists in the function-scoped
    `session` fixture used elsewhere, which is never committed (only
    rolled back for test isolation) -- so this fixture commits its setup
    for real instead.

    Returns `(invitee_access_token, raw_invitation_token, organization_id)`.
    """
    async with AsyncSession(engine, expire_on_commit=False) as setup_session:
        owner = await create_user(
            setup_session, "race-owner@example.com", "password12345"
        )
        organization = await create_organization(
            setup_session, name="Race Co", created_by=owner.id
        )
        await add_member(
            setup_session, organization_id=organization.id, user_id=owner.id
        )
        invitee = await create_user(
            setup_session, "race-member@example.com", "password12345"
        )
        raw_token = generate_invitation_token()
        await create_invitation(
            setup_session,
            organization_id=organization.id,
            email="race-member@example.com",
            token_hash=hash_invitation_token(raw_token),
            invited_by=owner.id,
            expires_at=invitation_token_expiry(),
        )
        await setup_session.commit()
        return (
            create_access_token(str(invitee.id)),
            raw_token,
            str(organization.id),
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_accepts_race_exactly_one_wins(
    engine: AsyncEngine,
    committed_owner_org_and_invitation: tuple[str, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two truly concurrent accepts of the *same* invitation token, each
    on its own connection/session/transaction (a real race, not two
    calls sharing one AsyncSession, which SQLAlchemy would refuse to
    interleave).

    An `asyncio.Barrier(2)` pins both requests to the same instant right
    before they hit the endpoint. That alone isn't enough to reliably
    land both coroutines inside `add_member`'s existence check at the
    same time though -- in practice, plain `asyncio.gather` scheduling
    tends to let one request run all the way through its check-then-
    insert before the other's check even starts, since neither the HTTP
    round trip nor a single local SELECT reliably yields the event loop
    back to the sibling task. So `get_member` (which `add_member` calls
    for its pre-insert check) is patched to rendezvous on a second
    barrier right after it resolves, forcing both requests to have
    completed their "does this membership exist yet" check -- and seen
    it not exist -- before either is allowed to proceed to the insert.
    That's the exact interleaving a purely-sequential duplicate-then-
    duplicate test can never exercise, and it's what the acceptance
    criteria in #56 calls for.

    Before the fix, the losing coroutine surfaced its `IntegrityError` as
    an unhandled 500 instead of a clean 409/400. After the fix, exactly
    one call gets 201 and the other a rejection, and the DB ends up with
    exactly one new membership row.
    """
    token_invitee, raw_token, org = committed_owner_org_and_invitation

    import kalekit.organization.repository as org_repository

    original_get_member = org_repository.get_member
    check_barrier = asyncio.Barrier(2)
    checks_seen = 0

    async def _synced_get_member(session, **kwargs):
        nonlocal checks_seen
        result = await original_get_member(session, **kwargs)
        # Only the two pre-insert checks (one per racing request) should
        # rendezvous here. If the fix's post-IntegrityError re-fetch also
        # went through this same patched function and tried to wait, it
        # would deadlock -- only one of the two coroutines ever needs
        # that re-fetch, since the winner returns from `add_member`
        # without ever hitting the `except` block.
        checks_seen += 1
        if checks_seen <= 2:
            await check_barrier.wait()
        return result

    monkeypatch.setattr(org_repository, "get_member", _synced_get_member)

    request_barrier = asyncio.Barrier(2)

    async def _accept() -> Response:
        await request_barrier.wait()
        return await _accept_with_own_session(engine, token_invitee, raw_token)

    response_a, response_b = await asyncio.gather(_accept(), _accept())

    statuses = sorted([response_a.status_code, response_b.status_code])
    assert statuses == [201, 409], (
        f"expected exactly one 201 and one 409, got {statuses} "
        f"(bodies: {response_a.text!r}, {response_b.text!r})"
    )

    async with AsyncSession(engine, expire_on_commit=False) as verify_session:
        result = await verify_session.execute(
            select(func.count())
            .select_from(OrganizationMember)
            .where(OrganizationMember.organization_id == uuid.UUID(org))
        )
        assert result.scalar_one() == 2  # owner + exactly one new member
