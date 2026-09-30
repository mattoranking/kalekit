"""The request's DB commit must happen before the response is sent (#238).

The shared `client` fixture overrides `get_db_session` with a plain
generator that never commits, so it cannot see this bug. The tests here
build an app that runs the real `get_db_session`, on the test
transaction, and make `commit` fail or record its timing.
"""

from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.types import ASGIApp, Receive, Scope, Send

from kalekit.postgres import get_db_read_session, get_db_session


class _InjectSession:
    """Stands in for AsyncSessionMiddleware, which create_app() skips
    under test: puts the test session where get_db_session looks."""

    def __init__(self, app: ASGIApp, session: AsyncSession) -> None:
        self.app = app
        self.session = session

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope.setdefault("state", {})["async_session"] = self.session
        await self.app(scope, receive, send)


@pytest_asyncio.fixture(loop_scope="session")
async def real_session_app(session: AsyncSession) -> FastAPI:
    from kalekit.main import create_app

    app = create_app()
    app.add_middleware(_InjectSession, session=session)

    async def _read_session() -> AsyncGenerator[AsyncSession]:
        yield session

    app.dependency_overrides[get_db_read_session] = _read_session
    return app


@pytest_asyncio.fixture(loop_scope="session")
async def real_client(real_session_app: FastAPI) -> AsyncGenerator[AsyncClient]:
    # raise_app_exceptions=False: an unhandled error must come back as the
    # 500 a real server would send, not be re-raised into the test.
    transport = ASGITransport(app=real_session_app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio(loop_scope="session")
async def test_failed_commit_is_not_reported_as_success(
    real_client: AsyncClient, register, login, auth_header
) -> None:
    await register("commit-fails@example.com")
    token = await login("commit-fails@example.com")

    rollbacks: list[bool] = []
    real_rollback = AsyncSession.rollback

    async def _rollback(self: AsyncSession) -> None:
        rollbacks.append(True)
        await real_rollback(self)

    with (
        patch.object(
            AsyncSession, "commit", side_effect=RuntimeError("connection lost")
        ),
        patch.object(AsyncSession, "rollback", _rollback),
    ):
        response = await real_client.post(
            "/v1/auth/logout-all", headers=auth_header(token)
        )

    assert response.status_code == 500, response.text
    assert rollbacks, "a failed commit must roll the session back"


@pytest.mark.asyncio(loop_scope="session")
async def test_successful_request_still_commits(
    real_client: AsyncClient, register, login, auth_header
) -> None:
    await register("commit-works@example.com")
    token = await login("commit-works@example.com")

    commits: list[bool] = []
    real_commit = AsyncSession.commit

    async def _commit(self: AsyncSession) -> None:
        commits.append(True)
        await real_commit(self)

    with patch.object(AsyncSession, "commit", _commit):
        response = await real_client.post(
            "/v1/auth/logout-all", headers=auth_header(token)
        )

    assert response.status_code == 204
    assert commits


@pytest.mark.asyncio(loop_scope="session")
async def test_forgot_password_token_is_committed_before_the_email_task_runs(
    real_client: AsyncClient, register
) -> None:
    await register("forgot-order@example.com")

    events: list[str] = []
    real_commit = AsyncSession.commit

    async def _commit(self: AsyncSession) -> None:
        await real_commit(self)
        events.append("commit")

    async def _send(*, to: str, token: str) -> None:
        events.append("email")

    with (
        patch.object(AsyncSession, "commit", _commit),
        patch("kalekit.auth.endpoints.send_password_reset_email", _send),
    ):
        response = await real_client.post(
            "/v1/auth/password/forgot", json={"email": "forgot-order@example.com"}
        )

    assert response.status_code == 202
    assert events == ["commit", "email"]


def _session_dependants(dependant: Dependant) -> list[Dependant]:
    found = [dependant] if dependant.call is get_db_session else []
    for sub in dependant.dependencies:
        found.extend(_session_dependants(sub))
    return found


def test_every_route_uses_get_db_session_with_function_scope() -> None:
    """`Depends(get_db_session)` without `scope="function"` commits after
    the response is sent. A new endpoint that forgets the scope fails here."""
    from kalekit.main import create_app

    checked: list[Any] = []
    for route in create_app().routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        for dep in _session_dependants(dependant):
            checked.append(route)
            assert dep.scope == "function", (
                f"{route.path} uses get_db_session without scope='function'"  # type: ignore[attr-defined]
            )
    assert checked, "no route uses get_db_session; the guard is checking nothing"
