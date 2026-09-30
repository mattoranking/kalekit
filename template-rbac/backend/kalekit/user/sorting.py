"""Allowlisted sort keys for GET /v1/users (#235).

A leading `-` means descending. The endpoint types `sort` as `UserSort`,
so any other value is rejected with a 422 before it reaches a query, and
the keys map to model columns here instead of being looked up by name
from the request.
"""

from typing import Literal

from sqlalchemy.sql.elements import ColumnElement

from kalekit.models.user import User

UserSort = Literal["created_at", "-created_at", "email", "-email"]

DEFAULT_USER_SORT: UserSort = "-created_at"

_COLUMNS = {
    "created_at": User.created_at,
    "email": User.email,
}


def user_order_by(sort: UserSort) -> list[ColumnElement]:
    """ORDER BY terms for `sort`, with `id` as the tie-breaker.

    `id` follows the same direction as the main key so that paging
    through rows with equal values stays stable.
    """
    descending = sort.startswith("-")
    column = _COLUMNS[sort.lstrip("-")]
    if descending:
        return [column.desc(), User.id.desc()]
    return [column.asc(), User.id.asc()]
