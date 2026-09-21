"""Resilience coverage for the role/permission Redis cache (#98).

`get_permissions_for_roles` uses Redis purely as a performance cache;
Postgres is the source of truth. A Redis outage must degrade to "one DB
query per check, still correct" -- on the read (`get`) and on the
write-back (`set`) -- never to an unhandled 500. Results are compared
against the DB loader so a fallback that silently returned less (or
more) than the DB says would fail too.
"""

import json

import pytest
import redis.exceptions
from sqlalchemy.ext.asyncio import AsyncSession

from kalekit.auth.permissions import (
    _load_permissions_from_db,
    get_permissions_for_roles,
)
from kalekit.auth.seed import ADMIN_ROLE


def _outage() -> redis.exceptions.ConnectionError:
    return redis.exceptions.ConnectionError("simulated redis outage")


class _FakeRedis:
    """Minimal in-memory stand-in; `get`/`set` can be made to raise."""

    def __init__(
        self, *, fail_get: bool = False, fail_set: bool = False
    ) -> None:
        self.fail_get = fail_get
        self.fail_set = fail_set
        self.store: dict[str, str] = {}
        self.set_calls = 0

    async def get(self, key: str) -> str | None:
        if self.fail_get:
            raise _outage()
        return self.store.get(key)

    async def set(self, key: str, value: str, **kwargs: object) -> None:
        self.set_calls += 1
        if self.fail_set:
            raise _outage()
        self.store[key] = value


def _patch_redis(monkeypatch: pytest.MonkeyPatch, fake: object) -> None:
    async def _get_redis():
        return fake

    monkeypatch.setattr("kalekit.auth.permissions.get_redis", _get_redis)


@pytest.mark.asyncio(loop_scope="session")
async def test_read_failure_falls_back_to_the_database(
    monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    expected = await _load_permissions_from_db(session, ADMIN_ROLE)
    assert expected  # the seeded admin role really has permissions
    _patch_redis(monkeypatch, _FakeRedis(fail_get=True))

    assert await get_permissions_for_roles(session, [ADMIN_ROLE]) == expected


@pytest.mark.asyncio(loop_scope="session")
async def test_write_back_failure_does_not_break_the_check(
    monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    expected = await _load_permissions_from_db(session, ADMIN_ROLE)
    fake = _FakeRedis(fail_set=True)
    _patch_redis(monkeypatch, fake)

    assert await get_permissions_for_roles(session, [ADMIN_ROLE]) == expected
    assert fake.set_calls == 1  # the write was attempted, and failed
    assert fake.store == {}


@pytest.mark.asyncio(loop_scope="session")
async def test_total_outage_falls_back_for_every_role(
    monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    expected = await _load_permissions_from_db(session, ADMIN_ROLE)
    _patch_redis(monkeypatch, _FakeRedis(fail_get=True, fail_set=True))

    # An unknown role has no permissions in the DB; it must simply
    # contribute nothing, not error.
    result = await get_permissions_for_roles(
        session, [ADMIN_ROLE, "no-such-role"]
    )
    assert result == expected


@pytest.mark.asyncio(loop_scope="session")
async def test_get_redis_failure_falls_back_to_the_database(
    monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    expected = await _load_permissions_from_db(session, ADMIN_ROLE)

    async def _boom():
        raise _outage()

    monkeypatch.setattr("kalekit.auth.permissions.get_redis", _boom)

    assert await get_permissions_for_roles(session, [ADMIN_ROLE]) == expected


@pytest.mark.asyncio(loop_scope="session")
async def test_failures_are_logged_as_warnings_with_exc_info(
    monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    calls: list[tuple[str, dict]] = []

    class _Logger:
        def warning(self, event: str, **kw: object) -> None:
            calls.append((event, dict(kw)))

    monkeypatch.setattr("kalekit.auth.permissions.logger", _Logger())
    _patch_redis(monkeypatch, _FakeRedis(fail_get=True, fail_set=True))

    await get_permissions_for_roles(session, [ADMIN_ROLE])

    assert calls
    assert all(kw.get("exc_info") is True for _, kw in calls)


@pytest.mark.asyncio(loop_scope="session")
async def test_healthy_redis_behaviour_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    expected = await _load_permissions_from_db(session, ADMIN_ROLE)
    fake = _FakeRedis()
    _patch_redis(monkeypatch, fake)

    # Miss: loads from the DB and writes back.
    assert await get_permissions_for_roles(session, [ADMIN_ROLE]) == expected
    key = f"role:{ADMIN_ROLE}:permissions"
    assert set(json.loads(fake.store[key])) == expected

    # Hit: served from the cache, no further write.
    assert await get_permissions_for_roles(session, [ADMIN_ROLE]) == expected
    assert fake.set_calls == 1
