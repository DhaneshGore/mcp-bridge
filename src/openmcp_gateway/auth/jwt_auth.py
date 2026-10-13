"""JWT/OIDC bearer-token authentication.

Validates RS256/ES256 JWT tokens using a JWKS endpoint (or an inline JWKS).
Keys are cached in memory and refreshed on a configurable interval or
immediately on an unknown ``kid``, at most once every 60 seconds to avoid
hammering the provider on bad tokens.

Install the optional extra to use this authenticator::

    pip install openmcp-gateway[jwt]
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from starlette.requests import HTTPConnection

from openmcp_gateway.auth.backends import bearer_token
from openmcp_gateway.auth.principal import ANONYMOUS, Principal
from openmcp_gateway.config import JWTConfig

logger = logging.getLogger(__name__)

_KID_MISS_COOLDOWN = 60.0  # minimum seconds between JWKS re-fetches triggered by unknown kid


def _import_jwt() -> Any:
    try:
        import jwt  # PyJWT

        return jwt
    except ImportError as exc:  # pragma: no cover
        from openmcp_gateway.config import ConfigError

        raise ConfigError(
            "auth.mode=jwt requires PyJWT: install openmcp-gateway[jwt]"
        ) from exc


class _JwksCache:
    """Async JWKS key cache with background refresh and kid-miss recovery."""

    def __init__(self, config: JWTConfig) -> None:
        self._config = config
        self._keys: dict[str, Any] = {}
        self._last_fetched: float = 0.0
        self._last_kid_miss: float = 0.0
        self._lock = asyncio.Lock()

    async def get(self, kid: str | None) -> Any | None:
        """Return the key for *kid*, refreshing the cache if needed."""
        now = time.monotonic()

        # Background refresh interval
        if now - self._last_fetched >= self._config.jwks_refresh_interval:
            await self._refresh()

        # kid-miss recovery (at most once per cooldown)
        if kid and kid not in self._keys:
            if now - self._last_kid_miss >= _KID_MISS_COOLDOWN:
                self._last_kid_miss = now
                await self._refresh()

        if kid:
            return self._keys.get(kid)
        # No kid in token header — return first key if only one exists
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return None

    async def _refresh(self) -> None:
        async with self._lock:
            # Re-check inside lock (another coroutine may have just refreshed)
            if time.monotonic() - self._last_fetched < 1.0:
                return
            try:
                keys = await self._fetch_keys()
                self._keys = keys
                self._last_fetched = time.monotonic()
                logger.debug("jwks refreshed", extra={"key_count": len(keys)})
            except Exception:
                logger.warning("jwks refresh failed; keeping existing keys", exc_info=True)

    async def _fetch_keys(self) -> dict[str, Any]:
        if self._config.inline_jwks is not None:
            return self._parse_jwks(self._config.inline_jwks)

        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(self._config.jwks_url or "")  # jwks_url validated in config
            resp.raise_for_status()
            return self._parse_jwks(resp.json())

    @staticmethod
    def _parse_jwks(jwks: dict[str, Any]) -> dict[str, Any]:
        jwt = _import_jwt()
        result: dict[str, Any] = {}
        for key_data in jwks.get("keys", []):
            kid = key_data.get("kid", "__default__")
            try:
                result[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            except Exception:
                try:
                    result[kid] = jwt.algorithms.ECAlgorithm.from_jwk(key_data)
                except Exception:
                    logger.debug("skipping unsupported jwk", extra={"kid": kid})
        return result


class JWTAuthenticator:
    """Validates OIDC/JWT bearer tokens and maps claims to a Principal."""

    def __init__(self, config: JWTConfig) -> None:
        self._config = config
        self._cache = _JwksCache(config)
        # Eagerly import to surface missing dependency at startup
        self._jwt = _import_jwt()

    async def authenticate(self, conn: HTTPConnection) -> Principal | None:
        raw = bearer_token(conn)
        if raw is None:
            return None
        if len(raw) > 8192:
            return None

        try:
            header = self._jwt.get_unverified_header(raw)
        except self._jwt.exceptions.DecodeError:
            return None

        kid = header.get("kid")
        key = await self._cache.get(kid)
        if key is None:
            logger.debug("jwt: no key for kid", extra={"kid": kid})
            return None

        decode_opts: dict[str, Any] = {
            "algorithms": self._config.algorithms,
            "options": {"verify_exp": True},
        }
        if self._config.issuer is not None:
            decode_opts["issuer"] = self._config.issuer
        if self._config.audience is not None:
            decode_opts["audience"] = self._config.audience

        try:
            claims: dict[str, Any] = self._jwt.decode(raw, key, **decode_opts)
        except self._jwt.exceptions.ExpiredSignatureError:
            logger.debug("jwt: token expired")
            return None
        except self._jwt.exceptions.InvalidAudienceError:
            logger.debug("jwt: invalid audience")
            return None
        except self._jwt.exceptions.InvalidIssuerError:
            logger.debug("jwt: invalid issuer")
            return None
        except self._jwt.exceptions.PyJWTError:
            logger.debug("jwt: validation failed", exc_info=True)
            return None

        name = str(claims.get(self._config.principal_claim, ""))
        if not name:
            logger.debug("jwt: principal claim missing or empty", extra={"claim": self._config.principal_claim})
            return None

        roles: frozenset[str] = frozenset()
        if self._config.roles_claim:
            raw_roles = claims.get(self._config.roles_claim, [])
            if isinstance(raw_roles, list):
                roles = frozenset(str(r) for r in raw_roles)

        return Principal(name=name, servers=frozenset({"*"}), roles=roles)


def build_jwt_authenticator(config: JWTConfig) -> JWTAuthenticator:
    return JWTAuthenticator(config)


class OptionalJWTAuthenticator:
    """JWT when a token is present, ANONYMOUS when none is presented."""

    def __init__(self, config: JWTConfig) -> None:
        self._inner = JWTAuthenticator(config)

    async def authenticate(self, conn: HTTPConnection) -> Principal | None:
        raw = bearer_token(conn)
        if raw is None:
            return ANONYMOUS
        # Token present — validate strictly; reject unknown tokens
        return await self._inner.authenticate(conn)
