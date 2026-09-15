from enum import StrEnum

from pydantic import GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import core_schema as cs


class Scope(StrEnum):
    web_default = "web_default"

    posts_read = "posts:read"
    posts_write = "posts:write"

    users_read = "users:read"
    users_write = "users:write"

    admin_read = "admin:read"
    admin_write = "admin:write"

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: cs.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        json_schema = handler(core_schema)
        json_schema = handler.resolve_ref_schema(json_schema)
        json_schema["enumNames"] = SCOPES_SUPPORTED_DISPLAY_NAMES
        return json_schema


RESERVED_SCOPES = {Scope.web_default}

SCOPES_SUPPORTED = [s.value for s in Scope if s not in RESERVED_SCOPES]

SCOPES_SUPPORTED_DISPLAY_NAMES: dict[Scope, str] = {
    Scope.web_default: "Default web access",
    Scope.posts_read: "Read posts",
    Scope.posts_write: "Create or modify posts",
    Scope.users_read: "Read user profiles",
    Scope.users_write: "Create or modify users",
    Scope.admin_read: "Read admin data",
    Scope.admin_write: "Modify admin settings",
}

SCOPES_READ = {Scope.posts_read, Scope.users_read}
SCOPES_WRITE = {Scope.posts_write, Scope.users_write}
SCOPES_ADMIN = {Scope.admin_read, Scope.admin_write}


def scope_to_set(scope: str) -> set[Scope]:
    return {Scope(x) for x in scope.strip().split()}
