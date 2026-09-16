"""Structural guard for the tenant-scoping filter.

Hybrid's authorization model layers a role check (`auth/roles.py`,
`ROLE_PERMISSIONS`) on top of an ownership gate, but the ownership gate
itself is the same `WHERE organization_id = ...` clause ABAC relies on
entirely: every tenant-scoped table is only ever read or written within
one organization at a time. Nothing about having roles removes the risk
of a future repository function simply forgetting to write that clause.

`tenant_select()` and `tenant_filter()` are the sanctioned way to build
that filter. Both require `organization_id` as a keyword-only argument,
so a call site can't drop the tenant scope the way it could drop a
positional argument or a hand-typed `.where(...)` clause -- there is no
form of the call that omits it.

Every repository function (and dependency) that reads or filters a
tenant-scoped table should go through one of these instead of writing
`Model.organization_id == ...` by hand.
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
