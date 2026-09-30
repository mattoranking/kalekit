"""Statement and round-trip counts for the RBAC N+1 fixes (#127, #128, #129).

* #127: `ensure_default_roles` (runs on every signup) issues a constant
  number of statements however many roles `roles.yaml` lists, and parses
  the file once.
* #128: `get_permissions_for_roles` reads all roles in one Redis call and
  loads the misses (or everything, during an outage) in one DB query.
* #129: change-password blocks every revoked session in one Redis write.

The counts are taken at the lowest layer that sees every call: the
SQLAlchemy engine's `before_cursor_execute` event for SQL, and
`Connection.send_packed_command` of redis-py for Redis (one call is one
network write, and a pipeline is one write however many commands it
holds). Neither counts wall-clock time.
"""

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
import redis.asyncio.connection
import redis.exceptions
import yaml
from httpx import AsyncClient
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from kalekit.auth.permissions import get_permissions_for_roles, get_redis
from kalekit.auth.scope import SCOPES_SUPPORTED
from kalekit.auth.seed import ADMIN_ROLE, VISITOR_ROLE, ensure_default_roles
from kalekit.config import settings
from kalekit.models.role import Permission, Role, RolePermission

_PASSWORD = "password12345"


# --- counting helpers -------------------------------------------------------


@contextmanager
def count_statements(engine: AsyncEngine) -> Iterator[list[str]]:
    """Collect every SQL statement the engine executes inside the block."""
    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _record)
    try:
        yield statements
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _record)


def count_redis_writes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_when: Callable[[bytes], bool] | None = None,
) -> list[bytes]:
    """Record every packet sent to Redis, one entry per network write.

    `fail_when(packet)` returning True makes that write raise a
    ConnectionError instead of reaching Redis (a simulated outage for
    just those commands).
    """
    packets: list[bytes] = []
    real = redis.asyncio.connection.Connection.send_packed_command

    async def _send(self, command, check_health=True):
        raw = (
            command
            if isinstance(command, (bytes, bytearray))
            else b"".join(bytes(part) for part in command)
        )
        packets.append(raw)
        if fail_when is not None and fail_when(raw):
            raise redis.exceptions.ConnectionError("simulated redis outage")
        return await real(self, command, check_health)

    monkeypatch.setattr(
        redis.asyncio.connection.Connection, "send_packed_command", _send
    )
    return packets


def _seed_file(path: Path, extra_roles: int) -> Path:
    """A roles.yaml with visitor, admin and `extra_roles` more roles, each
    holding a different slice of the supported scopes."""
    roles: dict[str, dict] = {
        VISITOR_ROLE: {
            "description": "Default role for new sign-ups",
            "permissions": [],
        },
        ADMIN_ROLE: {"description": "Full access", "permissions": ["*"]},
    }
    for i in range(extra_roles):
        roles[f"extra{i}"] = {
            "description": f"Extra role {i}",
            "permissions": SCOPES_SUPPORTED[: (i % len(SCOPES_SUPPORTED)) + 1],
        }
    path.write_text(yaml.safe_dump({"roles": roles}))
    return path


# --- #127: ensure_default_roles ----------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("extra_roles", [0, 6])
async def test_ensure_default_roles_statement_count_is_constant_in_roles(
    extra_roles: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session: AsyncSession,
    engine: AsyncEngine,
) -> None:
    """Once seeded, a signup's `ensure_default_roles` costs the same number
    of statements with 2 roles as with 8. The old code cost about 2 per
    role plus 1 per granted scope."""
    import kalekit.auth.seed as seed_module

    monkeypatch.setattr(
        seed_module, "ROLE_SEED_FILE", _seed_file(tmp_path / "roles.yaml", extra_roles)
    )
    await ensure_default_roles(session)  # first run seeds the rows

    with count_statements(engine) as statements:
        await ensure_default_roles(session)

    assert len(statements) <= 3, statements


@pytest.mark.asyncio(loop_scope="session")
async def test_ensure_default_roles_parses_the_seed_file_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    import kalekit.auth.seed as seed_module

    monkeypatch.setattr(
        seed_module, "ROLE_SEED_FILE", _seed_file(tmp_path / "roles.yaml", 1)
    )
    parses: list[None] = []
    real_load = yaml.safe_load

    def _counting_load(stream):
        parses.append(None)
        return real_load(stream)

    monkeypatch.setattr(seed_module.yaml, "safe_load", _counting_load)

    await ensure_default_roles(session)
    await ensure_default_roles(session)
    await ensure_default_roles(session)

    assert len(parses) == 1


@pytest.mark.asyncio(loop_scope="session")
async def test_ensure_default_roles_seeds_a_fresh_database_with_the_yaml_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    """The bulk path creates every role and grants every permission
    (`*` expands to all supported scopes) on a database with none."""
    import kalekit.auth.seed as seed_module

    monkeypatch.setattr(
        seed_module, "ROLE_SEED_FILE", _seed_file(tmp_path / "roles.yaml", 3)
    )

    visitor, admin = await ensure_default_roles(session)

    assert (visitor.name, admin.name) == (VISITOR_ROLE, ADMIN_ROLE)
    rows = (
        await session.execute(
            select(Role.name, Permission.name)
            .select_from(RolePermission)
            .join(Role, Role.id == RolePermission.role_id)
            .join(Permission, Permission.id == RolePermission.permission_id)
        )
    ).all()
    granted: dict[str, set[str]] = {}
    for role_name, permission_name in rows:
        granted.setdefault(role_name, set()).add(permission_name)
    assert granted[ADMIN_ROLE] == set(SCOPES_SUPPORTED)
    assert VISITOR_ROLE not in granted
    assert granted["extra0"] == set(SCOPES_SUPPORTED[:1])
    assert granted["extra2"] == set(SCOPES_SUPPORTED[:3])


# --- #128: get_permissions_for_roles -----------------------------------------


async def _seed_roles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session: AsyncSession,
    extra_roles: int = 2,
) -> list[str]:
    import kalekit.auth.seed as seed_module

    monkeypatch.setattr(
        seed_module,
        "ROLE_SEED_FILE",
        _seed_file(tmp_path / "roles.yaml", extra_roles),
    )
    await ensure_default_roles(session)
    return [ADMIN_ROLE, VISITOR_ROLE] + [f"extra{i}" for i in range(extra_roles)]


def _is_read(packet: bytes) -> bool:
    return b"MGET" in packet or b"\r\nGET\r\n" in packet


@pytest.mark.asyncio(loop_scope="session")
async def test_warm_cache_costs_one_redis_call_and_no_db_query(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session: AsyncSession,
    engine: AsyncEngine,
) -> None:
    roles = await _seed_roles(tmp_path, monkeypatch, session)  # 4 roles
    expected = await get_permissions_for_roles(session, roles)  # fills the cache

    packets = count_redis_writes(monkeypatch)
    with count_statements(engine) as statements:
        result = await get_permissions_for_roles(session, roles)

    assert result == expected == set(SCOPES_SUPPORTED)
    assert statements == []
    assert len(packets) == 1
    assert _is_read(packets[0])


@pytest.mark.asyncio(loop_scope="session")
async def test_cold_cache_costs_one_db_query_and_caches_every_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session: AsyncSession,
    engine: AsyncEngine,
) -> None:
    roles = await _seed_roles(tmp_path, monkeypatch, session)
    r = await get_redis()

    packets = count_redis_writes(monkeypatch)
    with count_statements(engine) as statements:
        result = await get_permissions_for_roles(session, roles)

    assert result == set(SCOPES_SUPPORTED)
    assert len(statements) == 1, statements
    # One read for all roles, one pipelined write-back for all roles.
    assert len(packets) == 2
    assert _is_read(packets[0])
    assert not _is_read(packets[1])
    for role, expected in {
        ADMIN_ROLE: set(SCOPES_SUPPORTED),
        VISITOR_ROLE: set(),
        "extra0": set(SCOPES_SUPPORTED[:1]),
        "extra1": set(SCOPES_SUPPORTED[:2]),
    }.items():
        key = f"role:{role}:permissions"
        assert set(json.loads(await r.get(key))) == expected
        assert 0 < await r.ttl(key) <= settings.ROLE_CACHE_TTL_SECONDS


@pytest.mark.asyncio(loop_scope="session")
async def test_partial_cache_loads_only_the_misses_in_one_query(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session: AsyncSession,
    engine: AsyncEngine,
) -> None:
    roles = await _seed_roles(tmp_path, monkeypatch, session)
    r = await get_redis()
    await r.set(f"role:{ADMIN_ROLE}:permissions", json.dumps(["cached:only"]))
    await r.set(f"role:{VISITOR_ROLE}:permissions", "not json")  # corrupt (#108)

    with count_statements(engine) as statements:
        result = await get_permissions_for_roles(session, roles)

    assert len(statements) == 1, statements
    # admin is served from the cache as-is, the corrupt visitor entry and
    # the two uncached roles come from the database.
    assert result == {"cached:only"} | set(SCOPES_SUPPORTED[:2])
    assert json.loads(await r.get(f"role:{VISITOR_ROLE}:permissions")) == []


@pytest.mark.asyncio(loop_scope="session")
async def test_redis_outage_costs_one_db_query_and_never_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session: AsyncSession,
    engine: AsyncEngine,
) -> None:
    roles = await _seed_roles(tmp_path, monkeypatch, session)
    r = await get_redis()
    await r.set(f"role:{ADMIN_ROLE}:permissions", json.dumps(["cached:only"]))

    count_redis_writes(monkeypatch, fail_when=lambda packet: True)
    with count_statements(engine) as statements:
        result = await get_permissions_for_roles(session, roles)

    assert len(statements) == 1, statements
    # The cached admin entry is unreachable, so the DB value wins.
    assert result == set(SCOPES_SUPPORTED)


@pytest.mark.asyncio(loop_scope="session")
async def test_unknown_role_yields_no_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, session: AsyncSession
) -> None:
    await _seed_roles(tmp_path, monkeypatch, session)

    assert await get_permissions_for_roles(session, ["no-such-role"]) == set()
    assert await get_permissions_for_roles(session, []) == set()


# --- #129: change-password revokes N sessions in one Redis write --------------


async def _login(client: AsyncClient, email: str) -> str:
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": _PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _is_family_block(packet: bytes) -> bool:
    return b"blocked_family:" in packet and b"\r\nSET\r\n" in packet


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_blocks_all_revoked_sessions_in_one_redis_write(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    email = "n-plus-one-change-pw@example.com"
    assert (await register(email)).status_code == 201
    current = await _login(client, email)
    for _ in range(3):
        await _login(client, email)  # three other sessions to revoke

    packets = count_redis_writes(monkeypatch)
    response = await client.post(
        "/v1/auth/change-password",
        headers={"Authorization": f"Bearer {current}"},
        json={"current_password": _PASSWORD, "new_password": "newpassword456"},
    )

    assert response.status_code == 200, response.text
    blocks = [p for p in packets if _is_family_block(p)]
    assert len(blocks) == 1
    assert (
        blocks[0].count(b"blocked_family:") == 3
    )  # 4 sessions, the current one is kept
    r = await get_redis()
    assert len([k async for k in r.scan_iter("blocked_family:*")]) == 3
    for key in [k async for k in r.scan_iter("blocked_family:*")]:
        assert (
            0
            < await r.ttl(key)
            <= settings.access_token_max_expire_minutes() * 60
            + settings.JWT_LEEWAY_SECONDS
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_change_password_redis_failure_is_logged_not_a_503(
    client: AsyncClient, register, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Redis failure while blocking the revoked sessions no longer
    fails the request: the committed token_version bump cuts the other
    sessions off, so it is a 200 (#195; it was a 503 under #177)."""
    email = "n-plus-one-change-pw-outage@example.com"
    assert (await register(email)).status_code == 201
    current = await _login(client, email)
    await _login(client, email)

    count_redis_writes(monkeypatch, fail_when=_is_family_block)
    response = await client.post(
        "/v1/auth/change-password",
        headers={"Authorization": f"Bearer {current}"},
        json={"current_password": _PASSWORD, "new_password": "newpassword456"},
    )
    assert response.status_code == 200
