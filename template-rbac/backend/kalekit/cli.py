"""Operator-only command-line utilities.

There is no first-user-becomes-admin shortcut (see auth/endpoints.py and
oauth/repository.py) -- every self-signup gets the default `visitor` role.
This is the only way to grant `admin`, and it's meant to be run out of
band by whoever operates the deployment, e.g.:

    uv run python -m kalekit.cli create-admin --email you@example.com
    uv run python -m kalekit.cli create-admin --email you@example.com \
        --password 'a strong one'

If a user with that email already exists (password or OAuth signup),
they're promoted in place. Otherwise --password is required and a new,
pre-verified password-login user is created directly as admin.

Also provides `generate-secret`, for producing a strong KALEKIT_JWT_SECRET_KEY
(config.py refuses to start outside development/testing without one):

    uv run python -m kalekit.cli generate-secret
    uv run python -m kalekit.cli generate-secret --write .env
"""

import argparse
import asyncio
import secrets
import sys
from pathlib import Path

import structlog

# Import the model package so every mapped class is registered before any
# query runs -- mirrors what kalekit.main does implicitly at app startup.
import kalekit.models  # noqa: F401
from kalekit.auth.repository import create_user, find_user_by_email
from kalekit.auth.seed import ADMIN_ROLE, assign_role, ensure_default_roles
from kalekit.postgres import create_async_engine
from kalekit.utils.db.database import create_async_sessionmaker

log = structlog.get_logger()


async def create_admin(email: str, password: str | None) -> None:
    engine = create_async_engine("kalekit")
    sessionmaker = create_async_sessionmaker(engine)

    try:
        async with sessionmaker() as session:
            user = await find_user_by_email(session, email)
            _, admin_role = await ensure_default_roles(session)

            if user is None:
                if not password:
                    print(
                        f"No user with email {email!r} exists yet. Pass "
                        "--password to create one as admin directly, or "
                        "have them sign up first and re-run this command "
                        "to promote the existing account.",
                        file=sys.stderr,
                    )
                    raise SystemExit(1)

                user = await create_user(
                    session, email, password, email_verified=True
                )
                await assign_role(session, user, admin_role)
                await session.commit()
                print(f"Created {email} and granted the admin role.")
                return

            role_names = {user_role.role.name for user_role in user.roles}
            if ADMIN_ROLE in role_names:
                print(f"{email} is already an admin.")
                return

            await assign_role(session, user, admin_role)
            await session.commit()
            print(f"Promoted {email} to admin.")
    finally:
        await engine.dispose()


def generate_secret(write_to: str | None) -> None:
    """Print a random JWT secret, or write it into a local .env file.

    Config validation (see kalekit/config.py) refuses to start outside
    development/testing with a default or under-32-byte
    KALEKIT_JWT_SECRET_KEY -- this is the tool it points operators at to
    fix that.
    """
    # 64 url-safe chars (48 random bytes), comfortably over the 32-byte
    # minimum config.py enforces.
    secret = secrets.token_urlsafe(48)

    if write_to is None:
        print(secret)
        return

    path = Path(write_to)
    line = f"KALEKIT_JWT_SECRET_KEY={secret}\n"

    lines = (
        path.read_text(encoding="utf-8").splitlines(keepends=True)
        if path.exists()
        else []
    )
    for i, existing in enumerate(lines):
        if existing.startswith("KALEKIT_JWT_SECRET_KEY="):
            lines[i] = line
            break
    else:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(line)

    path.write_text("".join(lines), encoding="utf-8")
    print(f"Wrote a new KALEKIT_JWT_SECRET_KEY to {path}.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m kalekit.cli",
        description="Operator utilities for a kalekit deployment.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_admin_parser = subparsers.add_parser(
        "create-admin",
        help="Create or promote a user to the admin role.",
    )
    create_admin_parser.add_argument(
        "--email", required=True, help="Email of the user to create or promote."
    )
    create_admin_parser.add_argument(
        "--password",
        default=None,
        help=(
            "Password to use if the user doesn't exist yet. Required to "
            "create a new admin; ignored (with a promotion) if the user "
            "already exists."
        ),
    )

    generate_secret_parser = subparsers.add_parser(
        "generate-secret",
        help="Generate a random JWT secret (prints it, or writes it to a .env file).",
    )
    generate_secret_parser.add_argument(
        "--write",
        dest="write_to",
        nargs="?",
        const=".env",
        default=None,
        metavar="PATH",
        help=(
            "Write (or replace) KALEKIT_JWT_SECRET_KEY in this file instead "
            "of printing the secret. Defaults to ./.env if given with no "
            "value."
        ),
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "create-admin":
        asyncio.run(create_admin(args.email, args.password))
    elif args.command == "generate-secret":
        generate_secret(args.write_to)


if __name__ == "__main__":
    main()
