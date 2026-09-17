from enum import StrEnum


class ClientType(StrEnum):
    """Which frontend/app a token was issued to.

    Carried as the access token's `aud` claim and the refresh token's
    `client` column. Binding tokens to a client is what stops a token
    minted for the consumer web/mobile app -- even one carrying
    `admin:*` scopes, e.g. because the signed-in user happens to hold
    the admin role -- from being accepted by admin-only routes: those
    routes additionally require `aud == "admin"` (see
    kalekit.auth.dependencies.require_admin_client), which only a
    token minted by the admin client ever carries. See #6.
    """

    web = "web"
    mobile = "mobile"
    admin = "admin"
