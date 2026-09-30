"""Search, filters and sorting on GET /v1/users (#235)."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import event, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.repository import find_user_by_email
from kalekit.models.user import User


async def _admin_token(register, login, promote_to_admin) -> str:
    await register("boss@example.com")
    await promote_to_admin("boss@example.com")
    return await login("boss@example.com", client_type="admin")


async def _get(client: AsyncClient, token: str, **params: object):
    return await client.get(
        "/v1/users/",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
    )


async def _list(client: AsyncClient, token: str, **params: object) -> dict:
    response = await _get(client, token, **params)
    assert response.status_code == 200, response.text
    return response.json()


def _emails(body: dict) -> list[str]:
    return [item["email"] for item in body["items"]]


async def _set_created_at(
    session: AsyncSession, email: str, created_at: datetime
) -> None:
    await session.execute(
        update(User).where(User.email == email).values(created_at=created_at)
    )
    await session.flush()


# --- q ---------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_q_matches_email_substring_case_insensitively(
    client: AsyncClient, register, login, promote_to_admin
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("Alice.Smith@example.com")
    await register("bob@example.com")

    body = await _list(client, token, q="ALICE")

    assert _emails(body) == ["Alice.Smith@example.com"]
    assert body["total"] == 1


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("wildcard", ["%", "_"])
async def test_q_treats_like_wildcards_literally(
    client: AsyncClient, register, login, promote_to_admin, wildcard: str
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("plain@example.com")
    await register(f"we{wildcard}ird@example.com")

    body = await _list(client, token, q=wildcard)

    assert _emails(body) == [f"we{wildcard}ird@example.com"]
    assert body["total"] == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_q_treats_backslash_literally(
    client: AsyncClient, register, login, promote_to_admin
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("plain@example.com")

    body = await _list(client, token, q="\\")

    assert body["items"] == []
    assert body["total"] == 0


# --- role ------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_role_filter_returns_only_holders_of_that_role(
    client: AsyncClient, register, login, promote_to_admin
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("visitor@example.com")

    admins = await _list(client, token, role="admin")
    visitors = await _list(client, token, role="visitor")
    nobody = await _list(client, token, role="no-such-role")

    assert _emails(admins) == ["boss@example.com"]
    assert admins["total"] == 1
    # boss also holds visitor (every registration grants it).
    assert sorted(_emails(visitors)) == ["boss@example.com", "visitor@example.com"]
    assert visitors["total"] == 2
    assert nobody["items"] == []
    assert nobody["total"] == 0


@pytest.mark.asyncio(loop_scope="session")
async def test_role_filter_does_not_hide_the_users_other_roles(
    client: AsyncClient, register, login, promote_to_admin
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    # boss holds both visitor (from register) and admin.
    body = await _list(client, token, role="admin")

    assert sorted(body["items"][0]["roles"]) == ["admin", "visitor"]


# --- is_active -------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_is_active_filter(
    client: AsyncClient, register, login, promote_to_admin, session
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("sleepy@example.com")
    user = await find_user_by_email(session, "sleepy@example.com")
    assert user is not None
    user.is_active = False
    await session.flush()

    inactive = await _list(client, token, is_active="false")
    active = await _list(client, token, is_active="true")
    everyone = await _list(client, token)

    assert _emails(inactive) == ["sleepy@example.com"]
    assert inactive["total"] == 1
    assert _emails(active) == ["boss@example.com"]
    assert active["total"] == 1
    assert everyone["total"] == 2


# --- combinations and total ------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_filters_combine_and_total_counts_the_filtered_set(
    client: AsyncClient, register, login, promote_to_admin, session
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    for n in range(5):
        await register(f"team{n}@example.com")
    await register("other@example.com")
    sleepy = await find_user_by_email(session, "team0@example.com")
    assert sleepy is not None
    sleepy.is_active = False
    await session.flush()

    body = await _list(
        client, token, q="TEAM", role="visitor", is_active="true", size=2, page=2
    )

    assert body["total"] == 4
    assert len(body["items"]) == 2
    assert body["page"] == 2
    assert all(e.startswith("team") and e != "team0@example.com" for e in _emails(body))


@pytest.mark.asyncio(loop_scope="session")
async def test_role_narrows_items_and_total_together_with_other_filters(
    client: AsyncClient, register, login, promote_to_admin, session
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("ops@example.com")
    await promote_to_admin("ops@example.com")
    await register("ops-visitor@example.com")
    await register("idle-ops@example.com")
    await promote_to_admin("idle-ops@example.com")
    idle = await find_user_by_email(session, "idle-ops@example.com")
    assert idle is not None
    idle.is_active = False
    await session.flush()

    with_q = await _list(client, token, q="ops", role="admin")
    with_active = await _list(client, token, role="admin", is_active="true")
    with_all = await _list(
        client, token, q="ops", role="admin", is_active="true", size=1
    )
    wrong_role = await _list(client, token, q="ops-visitor", role="admin")

    assert sorted(_emails(with_q)) == ["idle-ops@example.com", "ops@example.com"]
    assert with_q["total"] == 2
    assert sorted(_emails(with_active)) == ["boss@example.com", "ops@example.com"]
    assert with_active["total"] == 2
    assert _emails(with_all) == ["ops@example.com"]
    assert with_all["total"] == 1
    assert wrong_role["items"] == []
    assert wrong_role["total"] == 0


@pytest.mark.asyncio(loop_scope="session")
async def test_empty_role_and_empty_q_are_ignored(
    client: AsyncClient, register, login, promote_to_admin
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("a@example.com")

    body = await _list(client, token, q="", role="")

    assert body["total"] == 2


@pytest.mark.asyncio(loop_scope="session")
async def test_total_with_role_filter_counts_each_user_once(
    client: AsyncClient, register, login, promote_to_admin
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("a@example.com")

    # boss holds two roles; a join-based filter would count boss twice.
    body = await _list(client, token, q="boss")
    visitors = await _list(client, token, role="visitor")

    assert body["total"] == 1
    assert visitors["total"] == 2
    assert sorted(_emails(visitors)) == ["a@example.com", "boss@example.com"]


# --- sort ------------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_sort_by_email_and_created_at_in_both_directions(
    client: AsyncClient, register, login, promote_to_admin, session
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    await register("m@example.com")
    await register("z@example.com")
    await register("a@example.com")
    base = datetime(2024, 1, 1, tzinfo=UTC)
    await _set_created_at(session, "boss@example.com", base)
    await _set_created_at(session, "m@example.com", base + timedelta(days=1))
    await _set_created_at(session, "z@example.com", base + timedelta(days=2))
    await _set_created_at(session, "a@example.com", base + timedelta(days=3))

    default = await _list(client, token)
    newest = await _list(client, token, sort="-created_at")
    oldest = await _list(client, token, sort="created_at")
    email_asc = await _list(client, token, sort="email")
    email_desc = await _list(client, token, sort="-email")

    newest_first = [
        "a@example.com",
        "z@example.com",
        "m@example.com",
        "boss@example.com",
    ]
    assert _emails(default) == newest_first
    assert _emails(newest) == newest_first
    assert _emails(oldest) == list(reversed(newest_first))
    assert _emails(email_asc) == [
        "a@example.com",
        "boss@example.com",
        "m@example.com",
        "z@example.com",
    ]
    assert _emails(email_desc) == list(reversed(_emails(email_asc)))


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize(
    "bad", ["password_hash", "id", "-email,created_at", "", "EMAIL"]
)
async def test_unknown_sort_is_422(
    client: AsyncClient, register, login, promote_to_admin, bad: str
) -> None:
    token = await _admin_token(register, login, promote_to_admin)

    response = await _get(client, token, sort=bad)

    assert response.status_code == 422


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("sort", ["created_at", "-created_at"])
async def test_paging_is_stable_across_equal_sort_values(
    client: AsyncClient, register, login, promote_to_admin, session, sort: str
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    for n in range(6):
        await register(f"same{n}@example.com")
    same = datetime(2024, 5, 5, tzinfo=UTC)
    await session.execute(update(User).values(created_at=same))
    await session.flush()

    seen: list[str] = []
    for page in (1, 2, 3, 4):
        body = await _list(client, token, sort=sort, page=page, size=2)
        seen.extend(_emails(body))
    whole = await _list(client, token, sort=sort, size=100)

    assert len(seen) == 7
    assert len(set(seen)) == 7
    assert seen == _emails(whole)


# --- guard and shape -------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_filters_do_not_bypass_the_admin_guard(
    client: AsyncClient, register, login
) -> None:
    await register("admin@example.com")
    await register("visitor@example.com")
    token = await login("visitor@example.com", client_type="admin")

    response = await _get(client, token, q="admin", sort="email")

    assert response.status_code == 404


# --- query count -----------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_statement_count_per_page_is_constant(
    client: AsyncClient,
    engine: AsyncEngine,
    register,
    login,
    promote_to_admin,
) -> None:
    token = await _admin_token(register, login, promote_to_admin)
    for n in range(12):
        await register(f"bulk{n}@example.com")

    def count_for(size: int):
        statements: list[str] = []

        def _record(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        return statements, _record

    counts = []
    for size in (1, 5, 13):
        statements, record = count_for(size)
        event.listen(engine.sync_engine, "before_cursor_execute", record)
        try:
            body = await _list(client, token, q="@example", role="visitor", size=size)
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", record)
        assert len(body["items"]) == size
        counts.append(len(statements))

    assert counts[0] == counts[1] == counts[2], counts
