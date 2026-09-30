"""422 responses without the submitted values (#159).

FastAPI's default handler puts each error's `input` in the response. For
a password rejected by the length rule that is the password, and for an
error on the body as a whole (a missing field) it is the entire request
body, so it also carries the other password, token and code fields.
Logs and proxies that record response bodies would keep them.

The handler drops `input` from every validation error, not just the
ones on sensitive fields: the body-level case makes a per-field list
unsafe, and clients only need `loc`, `msg` and `type`. `ctx` is kept
(it holds limits such as `min_length`) except for string values that
contain the submitted input. Only `RequestValidationError` is handled;
HTTPException and other errors keep FastAPI's default handlers.
"""

from typing import Any

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def _contains_input(value: Any, submitted: Any) -> bool:
    return isinstance(value, str) and isinstance(submitted, str) and submitted in value


def scrub_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scrubbed: list[dict[str, Any]] = []
    for error in errors:
        submitted = error.get("input")
        clean = {k: v for k, v in error.items() if k not in ("input", "ctx")}
        ctx = error.get("ctx")
        if ctx:
            kept = {k: v for k, v in ctx.items() if not _contains_input(v, submitted)}
            if kept:
                clean["ctx"] = kept
        scrubbed.append(clean)
    return scrubbed


async def request_validation_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    errors = exc.errors()
    return JSONResponse(
        status_code=422,
        content={"detail": jsonable_encoder(scrub_errors(list(errors)))},
    )
