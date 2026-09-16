"""Structural guard for the ABAC tenant filter.

The ABAC gate in this codebase is `WHERE organization_id = ...` on every
query against a tenant-scoped table -- there's no separate permission
table to consult. That's fine as a pattern, but nothing stops a future
repository function from simply forgetting to write the clause.

`tenant_select()` and `tenant_filter()` are the sanctioned way to build
that filter. Both require `organization_id` as a keyword-only argument,
so a call site can't drop the tenant scope the way it could drop a
positional argument or a hand-typed `.where(...)` clause -- there is no
form of the call that omits it.

Every repository function that reads a tenant-scoped table should go
through one of these instead of writing `Model.organization_id == ...`
by hand.
"""

import uuid
from typing import Any

from sqlalchemy import ColumnElement, Select, select


def tenant_filter(
    model: type[Any], *, organization_id: uuid.UUID
) -> ColumnElement[bool]:
    """The `organization_id` equality clause for a tenant-scoped model.

    Use this when the query needs more than `select(model)` -- a join,
    a subset of columns, an aggregate -- and `tenant_select()` doesn't
    fit. Raises `TypeError` if `model` has no `organization_id` column,
    so calling this on a table that isn't tenant-scoped fails loudly
    instead of silently matching everything.
    """
    column = getattr(model, "organization_id", None)
    if column is None:
        raise TypeError(
            f"{model.__name__} has no organization_id column; "
            "tenant_filter() only applies to tenant-scoped models"
        )
    return column == organization_id


def tenant_select(model: type[Any], *, organization_id: uuid.UUID) -> Select[Any]:
    """`SELECT * FROM model WHERE organization_id = :organization_id`.

    The default way to read a tenant-scoped table. Build on top of the
    returned `Select` (`.order_by(...)`, `.limit(...)`, etc.) rather than
    re-filtering by hand.
    """
    return select(model).where(tenant_filter(model, organization_id=organization_id))
