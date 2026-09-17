import uuid
from collections.abc import AsyncGenerator, Callable
from pathlib import Path

import pytest
import pytest_asyncio

from kalekit.auth.client_type import ClientType
from kalekit.auth.repository import (
    create_user,
    find_user_by_email,
    store_refresh_token,
)
from kalekit.cli import build_parser, create_admin, generate_secret
from kalekit.cli import prune_refresh_tokens_cli as _prune_refresh_tokens_cli
from kalekit.config import MIN_JWT_SECRET_KEY_BYTES
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


def test_generate_secret_parser_defaults_to_printing() -> None:
    parser = build_parser()

    args = parser.parse_args(["generate-secret"])

    assert args.command == "generate-secret"
    assert args.write_to is None


def test_generate_secret_parser_write_defaults_to_dot_env() -> None:
    parser = build_parser()

    args = parser.parse_args(["generate-secret", "--write"])

    assert args.write_to == ".env"


def test_generate_secret_parser_write_accepts_explicit_path() -> None:
    parser = build_parser()

    args = parser.parse_args(["generate-secret", "--write", "backend/.env"])

    assert args.write_to == "backend/.env"


def test_generate_secret_prints_a_strong_secret(capsys: pytest.CaptureFixture) -> None:
    generate_secret(None)

    printed = capsys.readouterr().out.strip()

    assert len(printed.encode("utf-8")) >= MIN_JWT_SECRET_KEY_BYTES
    # Each call must be unique -- this is meant to feed a real secret.
    generate_secret(None)
    assert capsys.readouterr().out.strip() != printed


def test_generate_secret_writes_new_env_file(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"

    generate_secret(str(env_path))

    contents = env_path.read_text()
    lines = [
        line
        for line in contents.splitlines()
        if line.startswith("KALEKIT_JWT_SECRET_KEY=")
    ]
    assert len(lines) == 1
    secret = lines[0].split("=", 1)[1]
    assert len(secret.encode("utf-8")) >= MIN_JWT_SECRET_KEY_BYTES


def test_prune_refresh_tokens_parser_defaults_to_thirty_days() -> None:
    parser = build_parser()

    args = parser.parse_args(["prune-refresh-tokens"])

    assert args.command == "prune-refresh-tokens"
    assert args.older_than_days == 30


def test_prune_refresh_tokens_parser_accepts_explicit_window() -> None:
    parser = build_parser()

    args = parser.parse_args(["prune-refresh-tokens", "--older-than-days", "7"])

    assert args.older_than_days == 7


@pytest.mark.asyncio(loop_scope="session")
async def test_prune_refresh_tokens_cli_deletes_old_dead_rows_and_reports_count(
    cli_email: Callable[[str], str],
    capsys: pytest.CaptureFixture,
) -> None:
    from datetime import datetime, timedelta, timezone

    email = cli_email("cli-prune")

    engine = create_async_engine("kalekit")
    try:
        async with create_async_sessionmaker(engine)() as session:
            user = await create_user(
                session, email, "password123", email_verified=True
            )
            now = datetime.now(timezone.utc)
            token = await store_refresh_token(
                session,
                user.id,
                token_hash=f"cli-prune-{uuid.uuid4().hex}",
                expires_at=now + timedelta(days=30),
                client=ClientType.web,
            )
            token.revoked = True
            token.updated_at = now - timedelta(days=40)
            await session.commit()
    finally:
        await engine.dispose()

    await _prune_refresh_tokens_cli(30)

    printed = capsys.readouterr().out
    # Full-message match, not a loose substring: "1" in printed would
    # also pass if this over-deleted (e.g. "Deleted 11 ...") -- assert
    # the exact expected count so the test fails on over-deletion too.
    assert printed.strip() == "Deleted 1 dead refresh token row(s)."


@pytest.mark.asyncio(loop_scope="session")
async def test_prune_refresh_tokens_cli_exits_cleanly_for_negative_window(
    capsys: pytest.CaptureFixture,
) -> None:
    """A negative --older-than-days must surface as a clean,
    operator-facing error (message on stderr, non-zero exit) --  not
    a raw ValueError traceback out of prune_refresh_tokens."""
    with pytest.raises(SystemExit) as exc_info:
        await _prune_refresh_tokens_cli(-5)

    assert exc_info.value.code != 0

    captured = capsys.readouterr()
    assert "Deleted" not in captured.out
    assert captured.err.strip() != ""


def test_generate_secret_replaces_existing_line_in_place(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        "KALEKIT_ENV=production\n"
        "KALEKIT_JWT_SECRET_KEY=change-me-in-production\n"
        "KALEKIT_CORS_ORIGINS=https://example.com\n"
    )

    generate_secret(str(env_path))

    lines = env_path.read_text().splitlines()
    assert lines[0] == "KALEKIT_ENV=production"
    assert lines[1].startswith("KALEKIT_JWT_SECRET_KEY=")
    assert "change-me-in-production" not in lines[1]
    assert lines[2] == "KALEKIT_CORS_ORIGINS=https://example.com"
