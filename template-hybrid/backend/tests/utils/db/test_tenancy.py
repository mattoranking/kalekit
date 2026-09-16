import uuid

import pytest

from kalekit.chat.models import ChatMessage
from kalekit.models.user import User
from kalekit.utils.db.tenancy import tenant_filter, tenant_select


def test_tenant_select_filters_by_organization_id() -> None:
    org_id = uuid.uuid4()

    statement = tenant_select(ChatMessage, organization_id=org_id)

    compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
    assert "chat_messages.organization_id" in compiled
    assert org_id.hex in compiled.replace("-", "")


def test_tenant_filter_requires_organization_id_as_a_keyword() -> None:
    """`organization_id` has no positional form -- there's no way to call
    either helper without naming the tenant filter explicitly."""
    with pytest.raises(TypeError):
        tenant_filter(ChatMessage, uuid.uuid4())  # type: ignore[misc]


def test_tenant_select_rejects_models_without_organization_id() -> None:
    """Calling this on a table that isn't tenant-scoped fails loudly
    instead of silently building a statement with no filter at all."""
    with pytest.raises(TypeError):
        tenant_select(User, organization_id=uuid.uuid4())
