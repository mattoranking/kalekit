"""Security response headers and the trusted-host check for the API.

Which layer sets which header (each header is set in exactly one place so
layers cannot conflict):

- Here (API): X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and
  Cache-Control: no-store on the token-bearing /v1/auth/* and /v1/oauth/*
  responses. Also the Host allow-list (``KALEKIT_ALLOWED_HOSTS``).
- Traefik: Strict-Transport-Security, on the HTTPS routers only (local
  development runs over HTTP, so the app must not send it).
- Next.js apps: their own headers() in next.config.mjs.

This is a pure ASGI middleware, not BaseHTTPMiddleware, so the headers are
also added to responses produced by exception handlers (404, 401, 422).
A crash that reaches Starlette's outermost ServerErrorMiddleware (an
unhandled 500) is built outside this stack and does not get them.
"""

from fastapi import FastAPI
from starlette.datastructures import MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kalekit.config import settings

STATIC_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

# Responses under these prefixes carry tokens and must never be cached.
NO_STORE_PREFIXES: tuple[str, ...] = ("/v1/auth", "/v1/oauth")


def _is_no_store_path(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in NO_STORE_PREFIXES)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        no_store = _is_no_store_path(scope["path"])

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in STATIC_HEADERS.items():
                    headers[name] = value
                if no_store:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)


def configure_security(app: FastAPI) -> None:
    """Install the trusted-host check and the security headers.

    add_middleware puts the newest middleware outermost. The headers go on
    last so they also cover the 400 that TrustedHostMiddleware returns.
    """
    hosts = [h.strip() for h in settings.ALLOWED_HOSTS.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    app.add_middleware(SecurityHeadersMiddleware)
