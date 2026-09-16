import uuid
from collections.abc import AsyncGenerator, Callable

import pytest
import pytest_asyncio

from kalekit.auth.repository import create_user, find_user_by_email
from kalekit.cli import build_parser, create_admin
from kalekit.postgres import create_async_engine
from kalekit.utils.db.database import create_async_sessionmaker

# create_admin runs against its own engine/connection -- same as it would
# in production -- and commits directly, unlike the rollback-isolated
# `session` fixture the rest of the suite uses. So these tests track and
# clean up every user they create, to avoid leaking rows (and skewing
# user-count assertions) into whatever test runs next.


async def _delete_user(email: str) -> None:
    engine = create_async_engine("kalekit")
    try:
        async with create_async_sessionmaker(engine)() as session:
            user = await find_user_by_email(session, email)
            if user is None:
                return
            for user_role in list(user.roles):
                await session.delete(user_role)
            await session.delete(user)
            await session.commit()
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def cli_email() -> AsyncGenerator[Callable[[str], str]]:
    emails: list[str] = []

    def _make(prefix: str) -> str:
        email = f"{prefix}-{uuid.uuid4().hex}@example.com"
        emails.append(email)
        return email

    yield _make

    for email in emails:
        await _delete_user(email)


async def _fetch_role_names(email: str) -> list[str] | None:
    engine = create_async_engine("kalekit")
    try:
        async with create_async_sessionmaker(engine)() as session:
            user = await find_user_by_email(session, email)
            if user is None:
                return None
            return [user_role.role.name for user_role in user.roles]
    finally:
        await engine.dispose()


@pytest.mark.asyncio(loop_scope="session")
async def test_create_admin_creates_new_user_directly_as_admin(
    cli_email: Callable[[str], str],
) -> None:
    email = cli_email("cli-new")

    await create_admin(email, "a-strong-password")

    engine = create_async_engine("kalekit")
    try:
        async with create_async_sessionmaker(engine)() as session:
            user = await find_user_by_email(session, email)
            assert user is not None
            # Operator-provisioned accounts skip the emailed-link proof
            # password sign-ups require -- the operator is the trusted
            # party here, not an unverified self-signup.
            assert user.email_verified is True
    finally:
        await engine.dispose()

    assert await _fetch_role_names(email) == ["admin"]


@pytest.mark.asyncio(loop_scope="session")
async def test_create_admin_without_password_for_unknown_email_exits(
    cli_email: Callable[[str], str],
) -> None:
    email = cli_email("cli-missing-pw")

    with pytest.raises(SystemExit):
        await create_admin(email, None)

    assert await _fetch_role_names(email) is None


@pytest.mark.asyncio(loop_scope="session")
async def test_create_admin_promotes_an_existing_user(
    cli_email: Callable[[str], str],
) -> None:
    email = cli_email("cli-promote")

    engine = create_async_engine("kalekit")
    try:
        async with create_async_sessionmaker(engine)() as session:
            await create_user(session, email, "password123", email_verified=False)
            await session.commit()
    finally:
        await engine.dispose()

    # No --password needed: the user already exists, so this promotes
    # rather than creates.
    await create_admin(email, None)

    assert await _fetch_role_names(email) == ["admin"]


@pytest.mark.asyncio(loop_scope="session")
async def test_create_admin_is_idempotent(cli_email: Callable[[str], str]) -> None:
    email = cli_email("cli-idempotent")

    await create_admin(email, "password123")
    # Promoting an already-admin user again must not try to insert a
    # duplicate UserRole row (user_id, role_id) and blow up.
    await create_admin(email, None)

    assert await _fetch_role_names(email) == ["admin"]


def test_create_admin_parser_requires_email() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["create-admin"])


def test_create_admin_parser_password_is_optional() -> None:
    parser = build_parser()

    args = parser.parse_args(["create-admin", "--email", "a@example.com"])

    assert args.command == "create-admin"
    assert args.email == "a@example.com"
    assert args.password is None
