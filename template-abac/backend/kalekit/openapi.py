from enum import StrEnum
from typing import Any, NotRequired, TypedDict

from kalekit.config import Environment, settings


class OpenAPITag(TypedDict):
    name: str
    description: NotRequired[str]
    externalDocs: NotRequired[str]


class APITag(StrEnum):
    """
    Tags used by our documentation to better organize the endpoints.

    They should be set after the "group" tag, which is used to group the endpoints
    in the generated documentation

    **Example**
        ```py
        router = APIRouter(prefix="/users", tags=["users", APITag.public])
        ```
    """

    public = "public"
    mcp = "mcp"

    @classmethod
    def metadata(cls) -> list[OpenAPITag]:
        return [
            {
                "name": cls.public,
                "description": (
                    "Endpoints shown and documented in the kalekit API documentation"
                ),
            },
            {"name": cls.mcp, "description": "Endpoints enabled in the MCP server."},
        ]


class OpenAPIParameters(TypedDict):
    title: str
    summary: str
    version: str
    description: str
    docs_url: str | None
    redoc_url: str | None
    openapi_tags: list[dict[str, Any]]
    servers: list[dict[str, Any]] | None


OPENAPI_PARAMETERS: OpenAPIParameters = {
    "title": "Kalekit API",
    "summary": "Kalekit HTTP API",
    "version": "0.1.0",
    "description": "Discover all of the ways you can interact with the Kalekit API",
    "docs_url": None
    if settings.is_environment(
        {Environment.preview, Environment.staging, Environment.production}
    )
    else "/docs",
    "redoc_url": None
    if settings.is_environment(
        {Environment.preview, Environment.staging, Environment.production}
    )
    else "/redoc",
    "openapi_tags": APITag.metadata(),  # type: ignore
    "servers": [
        {
            "url": "https://api.kalekit.dev",
            "description": "Development environment",
        },
        {
            "url": "https://api.kalekit.one",
            "description": "Production environment",
        },
        {
            "url": "https://stage-api.kalekit.one",
            "description": "Staging environment",
        },
    ],
}

__all__ = [
    "OPENAPI_PARAMETERS",
    "APITag",
]
