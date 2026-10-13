"""RFC 8707 OAuth 2.1 Protected Resource Metadata endpoint.

Exposes ``/.well-known/oauth-protected-resource`` so that MCP clients can
auto-discover the authorization server without being told out-of-band.

This endpoint is intentionally unauthenticated (RFC 8707 §3 requires it to
be publicly accessible).  It is only mounted when ``auth.mode=jwt`` or an
``auth.oauth`` block is present in the config.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from openmcp_gateway.config import GatewayConfig


def build_wellknown_router(config: GatewayConfig) -> APIRouter:
    router = APIRouter(tags=["discovery"])
    oauth_cfg = config.auth.oauth

    @router.get(
        "/.well-known/oauth-protected-resource",
        summary="OAuth 2.1 Protected Resource Metadata (RFC 8707)",
        include_in_schema=True,
    )
    async def oauth_protected_resource(request: Request) -> JSONResponse:
        # Derive the resource URI: config > gateway base URL
        if oauth_cfg and oauth_cfg.resource:
            resource = oauth_cfg.resource
        else:
            base = str(request.base_url).rstrip("/")
            resource = base

        body: dict[str, Any] = {
            "resource": resource,
            "bearer_methods_supported": ["header"],
        }

        if oauth_cfg:
            if oauth_cfg.authorization_server_url:
                body["authorization_servers"] = [oauth_cfg.authorization_server_url]
            if oauth_cfg.scopes_supported:
                body["scopes_supported"] = oauth_cfg.scopes_supported

        return JSONResponse(body)

    return router
