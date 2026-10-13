"""Authentication backends.

`Authenticator` is the extension point: map an HTTP connection to a
`Principal` or None. Implementations must not trust identity headers set by
clients or proxies.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Protocol

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.requests import HTTPConnection

from openmcp_gateway.auth.principal import ANONYMOUS, Principal
from openmcp_gateway.config import AuthConfig

TOKEN_PREFIX = "omg_"  # noqa: S105 - a public prefix, not a secret


class Authenticator(Protocol):
    async def authenticate(self, conn: HTTPConnection) -> Principal | None: ...


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    """256 bits from the OS CSPRNG, URL-safe, with a recognisable prefix."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def bearer_token(conn: HTTPConnection) -> str | None:
    header = conn.headers.get("authorization")
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


class StaticTokenAuthenticator:
    """Opaque gateway API keys, configured as SHA-256 hashes.

    These are *not* OAuth access tokens: they carry no audience, expiry or
    scopes beyond what the gateway's own config assigns.
    """

    def __init__(self, config: AuthConfig) -> None:
        self._by_hash = self._build(config)

    @staticmethod
    def _build(config: AuthConfig) -> dict[str, Principal]:
        return {
            t.sha256: Principal(
                name=t.name,
                servers=frozenset(t.servers),
                roles=frozenset(t.roles),
                tool_rules=tuple((r.pattern, r.action) for r in t.tool_rules),
            )
            for t in config.tokens
        }

    def reload(self, config: AuthConfig) -> None:
        """Atomically update the token table (for config hot-reload)."""
        self._by_hash = self._build(config)

    async def authenticate(self, conn: HTTPConnection) -> Principal | None:
        token = bearer_token(conn)
        if token is None or len(token) > 512:
            return None
        # Lookup is by SHA-256 of a high-entropy secret: hash-table timing can
        # at most reveal digest prefixes, which do not help recover a token.
        return self._by_hash.get(hash_token(token))


class NoAuthAuthenticator:
    """Local development: every MCP caller is the anonymous principal."""

    async def authenticate(self, conn: HTTPConnection) -> Principal | None:
        return ANONYMOUS


class OptionalTokenAuthenticator:
    """Optional bearer token: anonymous when no token is presented; validated when one is."""

    def __init__(self, config: AuthConfig) -> None:
        self._by_hash = StaticTokenAuthenticator._build(config)

    def reload(self, config: AuthConfig) -> None:
        """Atomically update the token table (for config hot-reload)."""
        self._by_hash = StaticTokenAuthenticator._build(config)

    async def authenticate(self, conn: HTTPConnection) -> Principal | None:
        token = bearer_token(conn)
        if token is None:
            return ANONYMOUS
        if len(token) > 512:
            return None
        principal = self._by_hash.get(hash_token(token))
        # Unknown token → reject (don't silently downgrade to anonymous)
        return principal


class GatewayUser(AuthenticatedUser):
    """Starlette user carrying our Principal.

    Subclassing the SDK's AuthenticatedUser makes the SDK's Streamable HTTP
    session manager bind each MCP session to the principal that created it.
    """

    def __init__(self, principal: Principal) -> None:
        super().__init__(
            AccessToken(
                token="[redacted]",  # noqa: S106 - placeholder; never keep the presented secret
                client_id=principal.name,
                scopes=sorted(principal.roles),
            )
        )
        self.principal = principal


class GatewayAuthBackend(AuthenticationBackend):
    """Resolves MCP and admin identities independently.

    * `mcp` authenticator: NoAuth or static tokens depending on auth.mode.
    * Admin always uses static tokens (admin role checked by the route).
    """

    def __init__(self, mcp: Authenticator, admin: Authenticator, admin_prefix: str) -> None:
        self._mcp = mcp
        self._admin = admin
        self._admin_prefix = admin_prefix

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        path = conn.scope.get("path", "")
        is_admin_path = path == self._admin_prefix or path.startswith(self._admin_prefix + "/")
        authenticator = self._admin if is_admin_path else self._mcp
        principal = await authenticator.authenticate(conn)
        if principal is None:
            return None
        return AuthCredentials(sorted(principal.roles)), GatewayUser(principal)


def build_authenticators(config: AuthConfig) -> tuple[Authenticator, Authenticator]:
    tokens = StaticTokenAuthenticator(config)
    if config.mode == "bearer":
        mcp: Authenticator = tokens
    elif config.mode == "optional":
        mcp = OptionalTokenAuthenticator(config)
    elif config.mode == "jwt":
        from openmcp_gateway.auth.jwt_auth import build_jwt_authenticator

        assert config.jwt is not None  # enforced by AuthConfig validator
        mcp = build_jwt_authenticator(config.jwt)
    else:
        mcp = NoAuthAuthenticator()
    return mcp, tokens
