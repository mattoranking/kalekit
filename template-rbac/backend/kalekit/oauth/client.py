"""
Raw OAuth2 authorization-code flow clients for GitHub, Google, and X (Twitter).

Each provider is an instance of OAuthClient configured with its endpoints
and credentials. The class handles:
  1. Building the authorization redirect URL
  2. Exchanging the authorization code for tokens (via httpx)
  3. Fetching the user's profile from the provider's API

Twitter uses OAuth 2.0 with PKCE, so it additionally generates and
verifies a code_verifier/code_challenge pair.
"""

from __future__ import annotations

import hashlib
import secrets
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx

from kalekit.config import settings


@dataclass
class OAuthClient:
    authorize_url: str
    token_url: str
    userinfo_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: list[str] = field(default_factory=list)
    use_pkce: bool = False
    # Provider-specific query params that force the IdP to re-prompt for
    # credentials, used for step-up re-authentication (#16) when the
    # caller passes reauth=True to get_authorization_url. None means
    # this provider has no documented mechanism to force a fresh login
    # over an existing IdP session -- see the per-provider comments
    # below on OAUTH_PROVIDERS for what that means in practice.
    reauth_params: dict[str, str] | None = None

    # ---- Step 1: Build authorization redirect URL ----

    def get_authorization_url(
        self,
        state: str,
        extra_params: dict[str, str] | None = None,
    ) -> tuple[str, str | None]:
        """Return (redirect_url, code_verifier | None).

        code_verifier is only set when use_pkce=True (Twitter).
        Store it alongside state in Redis so the callback can send it
        in the token exchange.

        extra_params, when given, is merged into the query string --
        used to pass provider-specific params such as `prompt=login`
        to force re-authentication for step-up flows (#16).
        """
        params: dict[str, str] = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": state,
            "response_type": "code",
        }
        if self.scopes:
            params["scope"] = " ".join(self.scopes)
        if extra_params:
            params.update(extra_params)

        code_verifier: str | None = None
        if self.use_pkce:
            code_verifier = secrets.token_urlsafe(64)
            code_challenge = (
                urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode()).digest()
                )
                .rstrip(b"=")
                .decode()
            )
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        url = f"{self.authorize_url}?{urlencode(params)}"
        return url, code_verifier

    # ---- Step 2: Exchange authorization code for tokens ----

    async def exchange_code(
        self,
        code: str,
        code_verifier: str | None = None,
    ) -> dict:
        """POST to the provider's token endpoint, return the JSON response."""
        data: dict[str, str] = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                data=data,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            return response.json()

    # ---- Step 3: Fetch user profile ----

    async def get_user_info(self, access_token: str) -> dict:
        """GET the provider's userinfo endpoint with the access token."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.userinfo_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            response.raise_for_status()
            return response.json()


# ---------------------------------------------------------------------------
# Provider instances
# ---------------------------------------------------------------------------

google_oauth = OAuthClient(
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",
    userinfo_url="https://www.googleapis.com/oauth2/v2/userinfo",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    redirect_uri=settings.GOOGLE_REDIRECT_URI,
    scopes=["openid", "email", "profile"],
    # `prompt=login` is the standard OIDC param Google honors: it forces
    # the account chooser / credential check regardless of an existing
    # Google session in the browser. This is a real security guarantee
    # for step-up reauth (#16), not best-effort.
    reauth_params={"prompt": "login"},
)

# GitHub's OAuth authorize endpoint has no documented mechanism to force
# re-authentication over an existing GitHub session (its `login` param
# only pre-fills/suggests an account, it does not require re-entering
# credentials). There is therefore no `reauth_params` set here: a
# reauth=True request to GitHub falls back to the ordinary authorize
# URL and is best-effort only -- if the browser still has an active
# GitHub session, the provider may silently re-authorize without
# prompting for credentials. This is a documented, deliberate
# limitation of the provider, not an oversight -- see
# test_authorize_reauth_is_best_effort_for_github in
# tests/oauth/test_endpoints.py.
github_oauth = OAuthClient(
    authorize_url="https://github.com/login/oauth/authorize",
    token_url="https://github.com/login/oauth/access_token",
    userinfo_url="https://api.github.com/user",
    client_id=settings.GITHUB_CLIENT_ID,
    client_secret=settings.GITHUB_CLIENT_SECRET,
    redirect_uri=settings.GITHUB_REDIRECT_URI,
    scopes=["read:user", "user:email"],
)

# X (Twitter)'s OAuth 2.0 authorize endpoint has no confirmed equivalent
# either: `force_login` was an OAuth 1.0a parameter, and X's current
# OAuth 2.0 / PKCE docs do not document it (or `prompt=login`) as
# supported on /i/oauth2/authorize. Rather than silently claim a
# security guarantee this provider can't back, reauth_params is left
# unset here too -- best-effort only, same as GitHub above.
twitter_oauth = OAuthClient(
    authorize_url="https://twitter.com/i/oauth2/authorize",
    token_url="https://api.twitter.com/2/oauth2/token",
    userinfo_url="https://api.twitter.com/2/users/me",
    client_id=settings.TWITTER_CLIENT_ID,
    client_secret=settings.TWITTER_CLIENT_SECRET,
    redirect_uri=settings.TWITTER_REDIRECT_URI,
    scopes=["users.read", "tweet.read"],
    use_pkce=True,
)

OAUTH_PROVIDERS: dict[str, OAuthClient] = {
    "github": github_oauth,
    "google": google_oauth,
    "twitter": twitter_oauth,
}
